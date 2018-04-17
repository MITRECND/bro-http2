# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: btest-diff output

@load http2
@load http2/intel
