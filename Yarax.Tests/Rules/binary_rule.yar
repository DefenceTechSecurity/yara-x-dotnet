rule doc_file
{
	strings:
		$docfile_magic = {D0 CF 11 E0}

	condition:
		$docfile_magic at 0
}

rule docx_file
{
	strings:
		$zip_header = "PK"
		$word_file = "word/document.xml"
	
	condition:
		$zip_header at 0 and $word_file
}