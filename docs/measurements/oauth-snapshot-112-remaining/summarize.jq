[.[] | .value.shape as $shape | .value.phases[] | .+{shape:$shape}]
| group_by([.shape,.Phase])
| map({shape:.[0].shape,phase:.[0].Phase,n:length,
wall_ms:([.[].WallNS/1000000]|{min:min,max:max}),
cpu_ms:([.[]|(.UserUS+.SystemUS)/1000]|{min:min,max:max}),
alloc_bytes:([.[].TotalAlloc]|{min:min,max:max}),
mallocs:([.[].Mallocs]|{min:min,max:max})})
