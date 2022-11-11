const bns = require('bns-plus');
const { wire, DNSServer } = bns;
const Arweave = require('arweave');
let { default: ArDB } = require("ardb")
const JSON5 = require("json5")
const fs = require("fs");

global.config = JSON5.parse(fs.readFileSync("./config.json5", "utf8"));
(async () => {
  const { default: fetch } = await import("node-fetch")


  const arweave = Arweave.init({
    host: config.arweaveGateway,
    port: 443,
    protocol: 'https',
    timeout: 60000,
    logging: false,
  });

  const ardb = new ArDB(arweave);
  const server = new bns.DNSServer({
    tcp: true,
    async: true,
    timeout: 5000,
    edns: true,
    dnssec: true
  });
  const rootresolver = new bns.StubResolver({
    tcp: true,
    inet6: true,
    edns: true,
    dnssec: true
  })
  const recursiveresolver = new bns.StubResolver({
    tcp: true,
    inet6: true,
    edns: true,
    dnssec: true
  })
  rootresolver.setServers([config.rootHandshakeServer]);
  recursiveresolver.setServers([config.recursiveHandshakeServer]);

  server.on('query', async (req, res, rinfo) => {

    const [question] = req.question;
    if (question.name == "sl.") { return }

    let lookupResponse = (await rootresolver.lookup(question.name.toLowerCase(), "NS"))

    let nsServers = lookupResponse.authority.filter(record => record && record.data && record.data.ns).map(record => record.data.ns)
    const subresolver = new bns.StubResolver({
      tcp: true,
      inet6: true,
      edns: true,
      dnssec: true
    })

    try {
      let domainNameservers = (await Promise.all(nsServers.map(async serverName => {
        return lookupResponse.additional.find(r => r.name == serverName) ? [lookupResponse.additional.find(r => r.name == serverName).data.address] : (await recursiveresolver.lookup(serverName, "A")).answer.map(ans => ans.data.address)
      }))).reduce((pv, cv) => [...pv, ...cv], [])
      subresolver.setServers(domainNameservers)
      let domainNameserverRecords = (await subresolver.lookup(question.name.toLowerCase(), "NS")).authority.filter(record => record && record.data && record.data.ns).map(record => record.data.ns)
      let managerTxId = domainNameserverRecords.map(record => { return config.zones.some(zone => record.endsWith(zone)) ? record.slice(0, -config.zones.find(zone => record.endsWith(zone)).length) : null }).find(a => a)
      if (!managerTxId) {
        throw new Error("No manager TX found")
      }
      let managerTx = await fetch(`http://${config.arweaveGateway}/${managerTxId}`).then(res => res.json())
      if (!managerTx || typeof managerTx !== "object" || !Array.isArray(managerTx.managers)) {
        throw new Error("No managers found in tx")
      }

      let lastZonesTxSearch = await ardb.search("transactions").tags([{ name: "Target-NS-TxID", values: [managerTxId] }]).from(managerTx.managers).sort("HEIGHT_DESC").limit(1).exclude(["anchor"]).find()

      let lastZonesTx = lastZonesTxSearch.length > 0 ? lastZonesTxSearch[0].id : managerTx.recordsTx;
      if (!lastZonesTx) {
        throw new Error("No records tx found")
      }
      let zoneData = await fetch(`http://${config.arweaveGateway}/${lastZonesTx}`).then(res => res.text())
      res.answer = wire.fromZone(zoneData, question.name).filter(rec => rec.name == question.name)
      res.send()
    } catch (e) {
      console.warn(e);
      res.code = wire.codes.NXDOMAIN;
      res.send()
    }
  });

  server.open(53, '0.0.0.0');
})()