rule example_link
{
	strings:
		$url = /https?:\/\/example\.com\/?/

	condition:
		$url
}