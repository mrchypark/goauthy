package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	groupsPath      = "/Groups"
	groupSchema     = "urn:ietf:params:scim:schemas:core:2.0:Group"
	maxGroupMembers = 4096
)

var ErrInvalidGroup = errors.New("scim: invalid group")

// ErrGroupTooLarge marks a group projection above the supported size boundary:
// more members than maxGroupMembers, or an encoded request above the outbox
// request limit. It is always reported alongside the validation error of the
// boundary that rejected it (ErrInvalidGroup or ErrOutboxInvalid) so callers
// that classify by the older error keep working.
var ErrGroupTooLarge = errors.New("scim: group exceeds the supported projection size")

// GroupMember.Value is the remote SCIM User id, not the local externalId.
// Display is optional and is treated as presentation data only.
type GroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

// Group is the narrow outbound SCIM Group projection. Members are the
// complete desired state; SyncGroup replaces the remote representation when
// membership or identity changes.
type Group struct {
	Schemas     []string      `json:"schemas,omitempty"`
	ID          string        `json:"id,omitempty"`
	ExternalID  string        `json:"externalId"`
	DisplayName string        `json:"displayName"`
	Members     []GroupMember `json:"members,omitempty"`
}

// GroupRequest describes a group reconciliation or deletion.
type GroupRequest struct {
	Group        Group
	Delete       bool
	DeletePolicy DeletePolicy
}

// SyncGroup reconciles one complete desired group using POST or PUT. A
// displayName fallback is used only when externalId returned no match and the
// matching remote group is unmanaged (empty externalId); this prevents taking
// over a same-named managed group.
func (c *Client) SyncGroup(ctx context.Context, group Group) (Result, error) {
	return c.ReconcileGroup(ctx, GroupRequest{Group: group})
}

// DeleteGroup deletes a managed remote group, or unlinks its externalId under
// UnlinkRemote. Deletion deliberately searches externalId only.
func (c *Client) DeleteGroup(ctx context.Context, group Group, policy DeletePolicy) (Result, error) {
	return c.ReconcileGroup(ctx, GroupRequest{Group: group, Delete: true, DeletePolicy: policy})
}

// ReconcileGroup performs one stateless group operation.
func (c *Client) ReconcileGroup(ctx context.Context, req GroupRequest) (Result, error) {
	if c == nil || c.baseURL == nil || c.httpClient == nil || ctx == nil {
		return Result{}, ErrInvalidConfig
	}
	if err := validateGroup(req.Group); err != nil {
		return Result{}, err
	}
	if _, err := c.marshalGroupPayload(req.Group, false); err != nil {
		return Result{}, err
	}
	if req.Delete && req.DeletePolicy != DeleteRemote && req.DeletePolicy != UnlinkRemote {
		return Result{}, ErrInvalidConfig
	}
	remote, found, err := c.findGroup(ctx, req.Group, !req.Delete)
	if err != nil {
		return Result{}, err
	}
	if req.Delete {
		if !found {
			return Result{Action: ActionNoop}, nil
		}
		if req.DeletePolicy == UnlinkRemote {
			// Unlink is deliberately non-destructive: preserve the provider's
			// current name and members while clearing only our ownership marker.
			updated, err := c.putGroup(ctx, remote.ID, remote, true)
			if err != nil {
				return Result{}, err
			}
			if updated.ID != remote.ID {
				return Result{}, ErrIdentifierChanged
			}
			if updated.DisplayName != "" && (updated.ExternalID != "" || updated.DisplayName != remote.DisplayName || !sameMembers(updated.Members, remote.Members)) {
				return Result{}, ErrIdentifierChanged
			}
			return Result{Action: ActionUnlinked, RemoteID: remote.ID}, nil
		}
		if _, err := c.doGroup(ctx, http.MethodDelete, remote.ID, nil); err != nil {
			return Result{}, err
		}
		return Result{Action: ActionDeleted, RemoteID: remote.ID}, nil
	}
	if !found {
		created, err := c.postGroup(ctx, req.Group)
		if err != nil {
			return Result{}, err
		}
		if created.ExternalID != "" || created.DisplayName != "" {
			if created.ExternalID != req.Group.ExternalID || created.DisplayName != req.Group.DisplayName || !sameMembers(created.Members, req.Group.Members) {
				return Result{}, ErrIdentifierChanged
			}
		}
		return Result{Action: ActionCreated, RemoteID: created.ID}, nil
	}
	if sameGroup(remote, req.Group) {
		return Result{Action: ActionUnchanged, RemoteID: remote.ID}, nil
	}
	updated, err := c.putGroup(ctx, remote.ID, req.Group, false)
	if err != nil {
		return Result{}, err
	}
	if updated.ID != remote.ID {
		return Result{}, ErrIdentifierChanged
	}
	if updated.ExternalID != "" || updated.DisplayName != "" {
		if updated.ExternalID != req.Group.ExternalID || updated.DisplayName != req.Group.DisplayName || !sameMembers(updated.Members, req.Group.Members) {
			return Result{}, ErrIdentifierChanged
		}
	}
	return Result{Action: ActionUpdated, RemoteID: updated.ID}, nil
}

func (c *Client) findGroup(ctx context.Context, wanted Group, fallback bool) (Group, bool, error) {
	groups, err := c.listGroups(ctx, "externalId", wanted.ExternalID)
	if err != nil {
		return Group{}, false, err
	}
	if len(groups) == 1 {
		if groups[0].ExternalID != wanted.ExternalID {
			return Group{}, false, ErrIdentifierChanged
		}
		return groups[0], true, nil
	}
	if !fallback {
		return Group{}, false, nil
	}
	groups, err = c.listGroups(ctx, "displayName", wanted.DisplayName)
	if err != nil {
		return Group{}, false, err
	}
	if len(groups) == 0 {
		return Group{}, false, nil
	}
	if groups[0].DisplayName != wanted.DisplayName {
		return Group{}, false, ErrIdentifierChanged
	}
	if groups[0].ExternalID != "" && groups[0].ExternalID != wanted.ExternalID {
		return Group{}, false, ErrIdentifierChanged
	}
	return groups[0], true, nil
}

func (c *Client) listGroups(ctx context.Context, field, value string) ([]Group, error) {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + groupsPath
	u.RawPath = ""
	q := u.Query()
	q.Set("filter", field+` eq "`+escapeFilter(value)+`"`)
	q.Set("startIndex", "1")
	q.Set("count", "100")
	u.RawQuery = q.Encode()
	resp, err := c.request(ctx, http.MethodGet, &u, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !jsonContentType(resp.Header.Get("Content-Type")) {
		return nil, responseStatusError(resp.StatusCode)
	}
	body, err := boundedBody(resp.Body, c.maxResponseBytes)
	if err != nil {
		return nil, err
	}
	var page groupListResponse
	if err := decodeJSON(body, &page); err != nil || !hasSchema(page.Schemas, listResponseSchema) || page.TotalResults == nil || *page.TotalResults < 0 {
		return nil, ErrProtocol
	}
	if page.StartIndex != nil && *page.StartIndex != 1 {
		return nil, ErrProtocol
	}
	if page.ItemsPerPage != nil && *page.ItemsPerPage < 0 {
		return nil, ErrProtocol
	}
	if *page.TotalResults > 1 || *page.TotalResults == 1 && len(page.Resources) != 1 || *page.TotalResults == 0 && len(page.Resources) != 0 {
		if *page.TotalResults > 1 {
			return nil, ErrAmbiguous
		}
		return nil, ErrProtocol
	}
	if page.ItemsPerPage != nil && *page.ItemsPerPage != len(page.Resources) {
		return nil, ErrProtocol
	}
	for i := range page.Resources {
		if err := validateRemoteGroup(page.Resources[i]); err != nil {
			return nil, err
		}
	}
	return page.Resources, nil
}

type groupListResponse struct {
	Schemas      []string `json:"schemas"`
	Resources    []Group  `json:"Resources"`
	TotalResults *int     `json:"totalResults"`
	StartIndex   *int     `json:"startIndex"`
	ItemsPerPage *int     `json:"itemsPerPage"`
}

type groupPayload struct {
	Schemas     []string      `json:"schemas"`
	ExternalID  *string       `json:"externalId"`
	DisplayName string        `json:"displayName"`
	Members     []GroupMember `json:"members"`
}

func (c *Client) postGroup(ctx context.Context, group Group) (Group, error) {
	payload, err := c.marshalGroupPayload(group, false)
	if err != nil {
		return Group{}, err
	}
	return c.doGroup(ctx, http.MethodPost, "", payload)
}

func (c *Client) putGroup(ctx context.Context, id string, group Group, unlink bool) (Group, error) {
	if err := validRemoteID(id); err != nil {
		return Group{}, err
	}
	payload, err := c.marshalGroupPayload(group, unlink)
	if err != nil {
		return Group{}, err
	}
	return c.doGroup(ctx, http.MethodPut, id, payload)
}

func (c *Client) marshalGroupPayload(group Group, unlink bool) ([]byte, error) {
	members := canonicalMembers(group.Members)
	externalID := &group.ExternalID
	if unlink {
		externalID = nil
	}
	b, err := json.Marshal(groupPayload{Schemas: []string{groupSchema}, ExternalID: externalID, DisplayName: group.DisplayName, Members: members})
	if err != nil || len(b) > c.maxResponseBytes {
		return nil, ErrInvalidGroup
	}
	return b, nil
}

func (c *Client) doGroup(ctx context.Context, method, id string, body []byte) (Group, error) {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + groupsPath
	if id != "" {
		if err := validRemoteID(id); err != nil {
			return Group{}, err
		}
		u.Path += "/" + id
	}
	u.RawPath = ""
	resp, err := c.request(ctx, method, &u, body)
	if err != nil {
		return Group{}, err
	}
	defer resp.Body.Close()
	if method == http.MethodDelete {
		if resp.StatusCode != http.StatusNoContent {
			return Group{}, responseStatusError(resp.StatusCode)
		}
		data, err := boundedBody(resp.Body, c.maxResponseBytes)
		if err != nil {
			return Group{}, err
		}
		if !validOptionalJSON(data, resp.Header.Get("Content-Type")) {
			return Group{}, ErrProtocol
		}
		return Group{}, nil
	}
	if method == http.MethodPost && resp.StatusCode != http.StatusCreated || method == http.MethodPut && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return Group{}, responseStatusError(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNoContent {
		data, err := boundedBody(resp.Body, c.maxResponseBytes)
		if err != nil {
			return Group{}, err
		}
		if !validOptionalJSON(data, resp.Header.Get("Content-Type")) || len(data) != 0 {
			return Group{}, ErrProtocol
		}
		return Group{ID: id}, nil
	}
	data, err := boundedBody(resp.Body, c.maxResponseBytes)
	if err != nil {
		return Group{}, err
	}
	if len(data) == 0 && method == http.MethodPost {
		locationID, err := c.groupLocationID(resp.Header.Get("Location"))
		if err != nil {
			return Group{}, err
		}
		return Group{ID: locationID}, nil
	}
	if !jsonContentType(resp.Header.Get("Content-Type")) {
		return Group{}, ErrProtocol
	}
	var got Group
	if err := decodeJSON(data, &got); err != nil || validateRemoteGroup(got) != nil {
		return Group{}, ErrProtocol
	}
	return got, nil
}

func (c *Client) groupLocationID(raw string) (string, error) {
	location, err := url.Parse(raw)
	if err != nil || raw == "" || !location.IsAbs() || location.Scheme != c.baseURL.Scheme || location.Host != c.baseURL.Host || location.User != nil || location.RawQuery != "" || location.Fragment != "" || location.RawPath != "" {
		return "", ErrProtocol
	}
	prefix := strings.TrimRight(c.baseURL.Path, "/") + groupsPath + "/"
	if !strings.HasPrefix(location.Path, prefix) {
		return "", ErrProtocol
	}
	id := strings.TrimPrefix(location.Path, prefix)
	if validRemoteID(id) != nil {
		return "", ErrProtocol
	}
	return id, nil
}

func validateGroup(group Group) error {
	if len(group.Members) > maxGroupMembers {
		return fmt.Errorf("%w: %w", ErrInvalidGroup, ErrGroupTooLarge)
	}
	if group.ID != "" || !validIdentifier(group.ExternalID) || !validIdentifier(group.DisplayName) {
		return ErrInvalidGroup
	}
	if _, err := canonicalMembersChecked(group.Members); err != nil {
		return ErrInvalidGroup
	}
	return nil
}

func validateRemoteGroup(group Group) error {
	if validRemoteID(group.ID) != nil || !hasSchema(group.Schemas, groupSchema) || !validIdentifier(group.DisplayName) || group.ExternalID != "" && !validIdentifier(group.ExternalID) || len(group.Members) > maxGroupMembers {
		return ErrProtocol
	}
	if _, err := canonicalMembersChecked(group.Members); err != nil {
		return ErrProtocol
	}
	return nil
}

func canonicalMembers(members []GroupMember) []GroupMember {
	result, _ := canonicalMembersChecked(members)
	return result
}

func canonicalMembersChecked(members []GroupMember) ([]GroupMember, error) {
	if len(members) > maxGroupMembers {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGroup, ErrGroupTooLarge)
	}
	// Keep an empty desired state as [] rather than null: full replacement
	// semantics must clear remote membership deterministically.
	result := make([]GroupMember, len(members))
	copy(result, members)
	seen := make(map[string]struct{}, len(result))
	for _, member := range result {
		if validRemoteID(member.Value) != nil || member.Display != "" && !validIdentifier(member.Display) {
			return nil, ErrInvalidGroup
		}
		if _, ok := seen[member.Value]; ok {
			return nil, ErrInvalidGroup
		}
		seen[member.Value] = struct{}{}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Value == result[j].Value {
			return result[i].Display < result[j].Display
		}
		return result[i].Value < result[j].Value
	})
	return result, nil
}

func sameGroup(a, b Group) bool {
	return a.ExternalID == b.ExternalID && a.DisplayName == b.DisplayName && sameMembers(a.Members, b.Members)
}

func sameMembers(a, b []GroupMember) bool {
	aa, errA := canonicalMembersChecked(a)
	bb, errB := canonicalMembersChecked(b)
	if errA != nil || errB != nil || len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
