## 2024-05-24 - Pre-allocate Vec capacities for DashMap iterations
**Learning:** DashMap iteration can benefit from pre-allocating the Vec capacity since its size is known beforehand.
**Action:** Always use Vec::with_capacity(map.len()) instead of Vec::new() when iterating through DashMaps or any collection of known size where elements are pushed to a Vec.
