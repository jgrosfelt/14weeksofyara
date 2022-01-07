import "pe"

rule warzone_stringsimilarity
{
   meta:
      Author = "Justin Grosfelt"
      Website = "https://www.bethreatresilient.com/blog"
      Reference = ""
      Date = "2022-01-07"

    strings:

        $sqlite_1 = "sqlite3_column_type" nocase
        $sqlite_2 = "sqlite3_prepare_v2" nocase
        $sqlite_3 = "sqlite3_column_byte" nocase
        $sqlite_4 = "sqlite3_column_blob" nocase
        $sqlite_5 = "sqlite3_column_text" nocase
        $sqlite_6 = "sqlite3_step" nocase
        $sqlite_7 = "sqlite3_open_v2" nocase
        $sqlite_8 = "sqlite3_close" nocase
        $sqlite_9 = "sqlite3_open" nocase
        $sqlite_10 = "sqlite3_close_v2" nocase
        $sqlite_11 = "sqlite3_exec" nocase

        $warzone = "warzone160" nocase
        
        $str_1 = "software\\aerofox\\foxmailpreview" nocase
        $str_2 = "find.exe" nocase
        $str_3 = "accounts\\account.rec0" nocase
        $str_4 = "ueeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" nocase

    condition:
        (uint16(0) == 0x5a4d)
        and
        ($warzone
        and
        (5 of ($sqlite_*))
        and
        (2 of ($str_*)))
}


