rule Suspicious_Corrupted_ZIP_File {
    meta:
        description = "Detects potentially malicious corrupted ZIP files used in zero-day attacks"
        author = "Security Analyst"
        date = "2024-11-27"
        threat_level = 8

    strings:
        // Standard ZIP header signatures
        $zip_header = { 50 4B 03 04 }
        $zip_central_dir = { 50 4B 01 02 }
        $zip_end_central_dir = { 50 4B 05 06 }

        // Corrupted ZIP headers patterns
        $corrupted_header1 = { 50 4B C3 90 }
        $corrupted_header2 = { 50 4B 03 [2] 8F EF }
        
        // Suspicious patterns
        $susp_pattern1 = "Word/document.xml"
        $susp_pattern2 = "[Content_Types].xml"
        $susp_pattern3 = "_rels/.rels"
        
        // Suspicious strings
        $susp_str1 = "cmd.exe"
        $susp_str2 = "powershell"
        $susp_str3 = "AutoOpen"
        $susp_str4 = "Auto_Open"
        $susp_str5 = "Document_Open"

    condition:
        ($zip_header at 0) and
        (
            $corrupted_header1 or
            $corrupted_header2 or
            (
                not $zip_central_dir in (0..filesize) and
                any of ($susp_pattern*) and
                $zip_end_central_dir in (filesize-22..filesize)
            ) or
            any of ($susp_str*)
        )
}

rule Suspicious_Office_Recovery_File {
    meta:
        description = "Detects Office files with suspicious recovery patterns"
        author = "Security Analyst"
        date = "2024-11-27"
        threat_level = 7

    strings:
        $office_sig = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip_sig = { 50 4B 03 04 }
        
        $recovery1 = "WordDocument"
        $recovery2 = "PowerPoint Document"
        $recovery3 = "Workbook"
        $recovery4 = "_repair"
        
        $susp1 = "auto_open"
        $susp2 = "autoexec"
        $susp3 = "shell"
        $susp4 = "cmd.exe"

    condition:
        ($office_sig at 0 or $zip_sig at 0) and
        any of ($recovery*) and
        any of ($susp*)
}

rule ZIP_Structure_Anomaly {
    meta:
        description = "Detects anomalies in ZIP file structure"
        author = "Security Analyst"
        date = "2024-11-27"
        threat_level = 6

    strings:
        $zip_sig = { 50 4B 03 04 }
        $central_dir = { 50 4B 01 02 }
        $end_central_dir = { 50 4B 05 06 }
        $data_descriptor = { 50 4B 07 08 }

    condition:
        $zip_sig at 0 and
        (
            not $central_dir in (0..filesize) or
            not $data_descriptor in (0..filesize) or
            $end_central_dir in (filesize-22..filesize)
        )
}
