# Derived primary observations

Median [min, max], all in-process wall/CPU milliseconds; Go allocation KiB.
Only rows with three observations have three-repetition summaries. No tail percentiles.

| Operation/state | Phase | n | Wall ms | Process CPU ms | Allocated KiB |
| --- | --- | ---: | --- | --- | --- |
| session-empty | first | 3 | 15.652 [15.526, 16.169] | 2.810 [2.782, 3.132] | 194.250 [193.906, 194.500] |
| session-empty | post_validation_followup | 3 | 17.629 [14.189, 19.456] | 3.027 [2.694, 3.371] | 194.203 [193.617, 200.180] |
| session-live | first | 3 | 18.514 [16.340, 19.162] | 3.227 [2.812, 4.544] | 217.688 [211.297, 223.906] |
| session-live | post_validation_followup | 3 | 15.355 [13.772, 21.090] | 4.301 [2.798, 4.485] | 221.805 [220.484, 225.094] |
| session-expired | first | 3 | 27.971 [24.805, 36.472] | 14.525 [12.405, 16.878] | 216.523 [211.664, 216.914] |
| session-expired | post_validation_followup | 3 | 16.738 [14.521, 18.041] | 3.892 [3.627, 4.911] | 216.172 [215.781, 219.617] |
| interaction-empty | first | 3 | 16.739 [13.576, 17.633] | 3.169 [2.827, 4.765] | 182.133 [177.000, 184.688] |
| interaction-empty | post_validation_followup | 3 | 18.988 [15.325, 19.486] | 3.163 [3.000, 3.403] | 181.742 [176.781, 187.172] |
| interaction-live | first | 3 | 14.918 [14.503, 16.464] | 3.381 [2.741, 3.538] | 202.898 [199.086, 204.734] |
| interaction-live | post_validation_followup | 3 | 17.280 [14.200, 17.639] | 3.750 [2.175, 4.416] | 203.836 [202.820, 206.281] |
| interaction-expired | first | 3 | 19.847 [18.418, 20.727] | 6.917 [6.542, 7.725] | 203.250 [199.109, 203.469] |
| interaction-expired | post_validation_followup | 3 | 14.625 [14.518, 15.115] | 2.989 [2.139, 3.944] | 205.695 [203.859, 206.367] |
| code-empty | first | 3 | 17.931 [15.539, 21.499] | 4.253 [3.197, 4.510] | 243.664 [240.664, 246.070] |
| code-empty | post_validation_followup | 3 | 17.455 [14.455, 18.212] | 4.061 [2.861, 4.329] | 241.430 [240.852, 256.258] |
| code-live | first | 3 | 18.536 [14.838, 19.436] | 4.118 [3.521, 4.371] | 263.258 [263.164, 265.539] |
| code-live | post_validation_followup | 3 | 15.016 [14.880, 22.889] | 3.433 [2.760, 3.530] | 262.523 [261.539, 268.336] |
| code-expired | first | 3 | 37.408 [34.853, 47.970] | 18.502 [12.105, 28.963] | 262.422 [262.422, 270.391] |
| code-expired | post_validation_followup | 3 | 18.351 [16.797, 19.061] | 3.554 [3.494, 4.684] | 265.883 [265.195, 271.758] |
| redemption-empty | first | 3 | 23.594 [19.171, 24.097] | 7.971 [6.224, 8.088] | 704.539 [681.008, 711.336] |
| redemption-empty | post_validation_followup | 3 | 31.136 [28.771, 45.241] | 8.142 [6.765, 9.300] | 691.469 [658.227, 692.797] |
| redemption-live | first | 3 | 23.069 [17.940, 28.733] | 8.496 [6.866, 13.891] | 729.227 [712.711, 749.305] |
| redemption-live | post_validation_followup | 3 | 26.063 [18.431, 26.771] | 6.352 [5.827, 10.794] | 678.875 [660.922, 698.336] |
| redemption-expired | first | 3 | 52.561 [34.638, 64.204] | 27.337 [22.049, 46.766] | 731.094 [729.812, 741.141] |
| redemption-expired | post_validation_followup | 3 | 18.345 [17.588, 32.235] | 5.519 [5.460, 6.918] | 702.602 [665.922, 703.484] |
| client_credentials-empty | first | 3 | 33.526 [33.263, 34.149] | 6.336 [5.863, 7.602] | 408.094 [402.500, 425.906] |
| client_credentials-empty | post_validation_followup | 3 | 42.470 [41.971, 80.243] | 7.985 [5.912, 10.730] | 423.609 [422.141, 426.438] |
| client_credentials-live | first | 3 | 36.284 [35.901, 38.598] | 8.148 [8.113, 11.204] | 455.203 [446.828, 466.000] |
| client_credentials-live | post_validation_followup | 3 | 34.024 [30.490, 35.916] | 9.687 [7.302, 15.554] | 464.227 [446.219, 465.242] |
| client_credentials-expired | first | 3 | 50.259 [36.140, 56.242] | 20.194 [12.815, 26.887] | 454.523 [453.164, 456.086] |
| client_credentials-expired | post_validation_followup | 3 | 33.712 [32.346, 37.906] | 8.935 [5.373, 10.811] | 449.578 [446.266, 460.984] |

Empty bracket wall ms, n=45: 0.000 [0.000, 0.001]. No subtraction.
