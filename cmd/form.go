package cmd

import (
	"fmt"
)

func ScanForm(scheme, hostname string) string {
	scanform := fmt.Sprintf(`
<html>
<h1><a>TCPScan </a></h1>
<form action="%v://%v/scanform/">
	<p>Use this form to submit a system to be scanned from this host. </p>
	<h2>Options</h2>
	<hr>
	<input id="ping" name="ping" type="checkbox" value="1" />Ping<br>
	<input id="sslcheck" name="sslcheck" type="checkbox" value="1" />SSL Check<br>
	<input id="dnsresolve" name="dnsresolve" type="checkbox" value="1" />DNS Resolve<br>
	<textarea id="hostlist" name="hostlist" rows="20" cols="80">127.0.0.1:22</textarea><br>
	<input id="saveForm" class="button_text" type="submit" name="Submit" value="Submit" />
	<input id="saveForm" class="button_text" type="submit" name="Build Payload" value="buildjson" />
	<p>Please select your Output format:</p>
	<input type="radio" id="json" name="output" value="json">
	<label for="male">JSON</label><br>
	<input type="radio" id="jsonf" name="output" value="jsonf">
	<label for="female">JSON Format</label><br>
	<input type="radio" id="html" name="output" checked="checked" value="html">
	<label for="female">HTML</label><br>
	<input type="radio" id="gridt" name="output" value="gridt">
	<label for="female">Grid</label><br>
</form>
<br>Submit a host or a list of hosts. Format can be of:
<pre>
http://my.domain.net
https://my2.domain.net
ntp://my3.domain.net
samba://my4.domain.net
10.1.1.23:87
</pre>
<h2>Build JSON Payload</h2>
To build the payload for a restcall click the 'Build Payload' button above. YOu will then be given the JSON payload and the URL to perform the REST call.
</html>`, scheme, hostname, scheme)
	return scanform
}
