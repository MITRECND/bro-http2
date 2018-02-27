
signature dpd_http2 {
	
	ip-proto == tcp
	

	# ## TODO: Define the payload. When Bro sees this regex, on
	# ## any port, it will enable your analyzer on that
	# ## connection.

	# THIS DOESNT WORK!!! WHY?
	#payload /^PRI * HTTP\/2.0\r\n\r\nSM\r\n\r\n/

	enable "http2"
}
