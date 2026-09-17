package storage

import (
	"context"
	"errors"
	"fmt"

	kitlog "github.com/go-kit/log"
	"github.com/mrchypark/rhiza"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/gcs"
	"github.com/thanos-io/objstore/providers/s3"
)

// OpenObjectStore opens the production bucket used by Rhiza without opening a
// database. Callers must close the returned bucket.
func OpenObjectStore(ctx context.Context, config rhiza.Config) (objstore.Bucket, error) {
	if config.ObjStoreBucket == "" {
		return nil, errors.New("object-store bucket is required")
	}

	switch config.ObjStoreProvider {
	case "s3":
		bucket, err := s3.NewBucketWithConfig(kitlog.NewNopLogger(), s3.Config{
			Bucket: config.ObjStoreBucket, Endpoint: config.ObjStoreEndpoint, Region: config.ObjStoreRegion,
			Insecure: config.ObjStoreInsecure, AWSSDKAuth: config.ObjStoreAccessKey == "",
			AccessKey: config.ObjStoreAccessKey, SecretKey: config.ObjStoreSecretKey,
			SessionToken: config.ObjStoreSessionToken, MaxRetries: config.ObjStoreRetries,
		}, "rhiza", nil)
		if err != nil {
			return nil, errors.New("open s3 object store")
		}
		return bucket, nil
	case "gcs":
		providerConfig := gcs.DefaultConfig
		providerConfig.Bucket = config.ObjStoreBucket
		providerConfig.ServiceAccount = config.ObjStoreServiceAccount
		providerConfig.MaxRetries = config.ObjStoreRetries
		bucket, err := gcs.NewBucketWithConfig(ctx, kitlog.NewNopLogger(), providerConfig, "rhiza", nil)
		if err != nil {
			return nil, errors.New("open gcs object store")
		}
		return bucket, nil
	default:
		return nil, fmt.Errorf("unsupported object-store provider %q", config.ObjStoreProvider)
	}
}
