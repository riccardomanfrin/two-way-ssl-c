Mix.install([{:cowboy, "~> 2.9.0"}])

defmodule Cert do
  require Record
  @certificate_def Record.extract(:Certificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl") |> IO.inspect()
  @tbs_certificate_def Record.extract(:TBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  Record.defrecord(:certificate, :Certificate, @certificate_def)
  Record.defrecord(:tbs_certificate, :TBSCertificate, @tbs_certificate_def)
  def get_userid(certificate(tbsCertificate: tbs_certificate(subject: {:rdnSequence, atnv_list}))) do
    res = for [{:AttributeTypeAndValue, {0, 9, 2342, 19200300, 100, 1, 1}, uid}] <- atnv_list, do: uid
    <<12, _len, uid::binary>> = List.first(res)
    #https://www.rfc-editor.org/rfc/rfc2798
    # ( 0.9.2342.19200300.100.1.1
    # NAME 'uid'
    # EQUALITY caseIgnoreMatch
    # SUBSTR caseIgnoreSubstringsMatch
    # SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
    uid |> String.downcase
  end
  def get_userid(_), do: nil
end

certsPath = 'keys'

defmodule Toppage do
  @authorized_users ["foo", "bar", "zoo", "mickey mouse", "anythinggoes"]
  def init(req, _userctx) do
    #IO.inspect {req, userctx}
    client_cert = :cowboy_req.cert(req) #|> IO.inspect(limit: :infinity)
    certificate  = :public_key.der_decode(:Certificate, client_cert)
    user = Cert.get_userid(certificate)
    req = if user in @authorized_users do
        :cowboy_req.reply(200, %{
          "content-type" => "text/plain"
        }, "Hello World user #{user}! You are authorized", req)
      else
        :cowboy_req.reply(401, %{
          "content-type" => "text/plain"
        }, "Sorry user #{user}.. You are unauthorized", req)
      end

    req =
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
        (_, {:bad_cert, :selfsigned_peer}, _userState) -> {:fail, "No self signed certs allowed"}; # Allow self-signed certificates
        (_,{:bad_cert, _} = reason, _) -> {:fail, reason};
        (_,{:extension, _}, userState) -> {:unknown, userState};
        (_, :valid, _userState) -> {:fail, "Peer not validated"};
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
