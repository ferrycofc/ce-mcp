# Findings

- MemScan firstScan/nextScan require input values as strings; rtRounded preserves CE's decimal precision rules.
- FoundList is 0-indexed and needs initialize after scan, deinitialize before next scan.
- waitTillDone must run off the CE main thread; all scan object setup and result access return via synchronize.
- CE documents soUnknownValue only for firstScan, not nextScan. Do not silently substitute comparison modes.
- MemoryRecord Active controls freezing; use stable record ID, not shifting table index.
- Scan state belongs to one PID and must be discarded on attachment change; frozen records created by bridge must be unfrozen before attachment changes to avoid writes into another target.
- Empty scan result test reproduced `{}` instead of `[]`; bundled json.lua encode_table explicitly supports metatable.isArray. Both results and process lists now declare arrays at source (two independent evidence checks: runtime plus serializer source).
- Live-value fixture independently changed target memory after scan and FoundList.Value remained cached. FoundList represents saved results, not a live memory reader. Result pages now use FoundList.Address plus typed reads of current memory; unreadable entries carry an error rather than hiding all results.
- CE unknown snapshot FoundCount/getProgress report captured bytes, while FoundList.Count is 0 until refinement. Responses declare snapshot=true and total_kind=bytes; enumerated results use total_kind=addresses. All 10 next modes successfully refine native unknown snapshots.
- Existing CE registry settings already redirect scanner data to E:\CEBUFFER\ (`Don't use tempdir`=1). Restart environment TEMP/TMP additionally points to E:\workspace\ce-mcp\work\temp. No scanner settings changed.
