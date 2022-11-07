Mix.install([{:cowboy, "~> 2.9.0"}])

certsPath = 'keys'

defmodule Toppage do
  def init(req, userctx) do
    #IO.inspect {req, userctx}
    client_cert = :cowboy_req.cert(req) #|> IO.inspect(limit: :infinity)
    :public_key.pem_decode(client_cert) #|> IO.inspect()
    req = :cowboy_req.reply(200, %{
        "content-type" => "text/plain"
      }, "Hello World!", req)
    {:ok, req, []}
  end
end

dispatch = :cowboy_router.compile([
  {:_, [
      {'/', Toppage, []}
  ]}
])

[port, sleepseconds | _dontcare] = System.argv()

name = :example
{:ok, _} = :cowboy.start_tls(name,
  [
    ip: {127,0,0,1}, #bind to 127.0.0.1 only
    port: String.to_integer(port),
    cacertfile: certsPath ++ '/ca_cert.pem',
    certfile: certsPath ++ '/server_cert.pem',
    keyfile: certsPath ++ '/server_key.pem',
    fail_if_no_peer_cert: true,
    verify: :verify_peer, #you need this for :cowboy_req.cert to not return :undefined
                          #https://ninenines.eu/docs/en/cowboy/2.9/manual/cowboy_req.cert/
    verify_fun: {fn
        (_, {:bad_cert, :selfsigned_peer}, userState) -> {:fail, "No self signed certs allowed"}; # Allow self-signed certificates
        (_,{:bad_cert, _} = reason, _) -> {:fail, reason};
        (_,{:extension, _}, userState) -> {:unknown, userState};
        (_, :valid, userState) -> {:fail, "Peer not validated"};
        (_, :valid_peer, userState) -> {:valid, userState}
      end, []}
  ],
  %{env: %{dispatch: dispatch}})

port = :ranch.get_port(name)
IO.puts(
  """
  Started HTTPs server on port #{port} ...
  Send a request to me with (-k ignores the self signed CA warning)

      curl -v -k https://127.0.0.1:8443

  or with

      curl -v --cacert ../keys/ca_cert.pem https://127.0.0.1:8443

  The latter explicitly tells curls to trust the CA provided by ca_cert.pem

  For mutual auth:

  curl -v --cert ../keys/client_cert.pem --key ../keys/client_key.pem --cacert ../keys/ca_cert.pem https://127.0.0.1:8443
  """)

Process.sleep(String.to_integer(sleepseconds) * 1000)
