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
    if (config.zones.some(zone => question.name.toLowerCase().endsWith(zone))) {
      const rr = new wire.Record();

      rr.name = question.name.toLowerCase();
      rr.type = wire.types.A;
      rr.ttl = 3600;
      rr.data = new wire.ARecord();
      rr.data.address = config.publicIp;

      res.answer.push(rr);
      res.send();

      return
    }
    let lookupResponse = (await rootresolver.lookup(question.name.toLowerCase(), "NS"))

    let nsServers = lookupResponse.authority.filter(record => record && record.data && record.data.ns).map(record => record.data.ns)
    const subresolver = new bns.StubResolver({
      tcp: true,
      inet6: true,
      edns: true,
      dnssec: true
    })
    let nsLookUpRes = {};
    try {
      let rootManagerTxId = nsServers.filter(n => n).map(record => { return config.zones.some(zone => record.endsWith(zone)) ? record.slice(0, -config.zones.find(zone => record.endsWith(zone)).length) : null }).find(a => a)
      if (!rootManagerTxId) {
        let domainNameservers = (await Promise.all(nsServers.map(async serverName => {
          return lookupResponse.additional.find(r => r.name == serverName) ? [lookupResponse.additional.find(r => r.name == serverName).data.address] : (await recursiveresolver.lookup(serverName, "A")).answer.map(ans => ans.data.address)
        }))).reduce((pv, cv) => [...pv, ...cv], []).filter(ns => ns)



        subresolver.setServers(domainNameservers.filter(n => n))

        nsLookUpRes = await subresolver.lookup(question.name.toLowerCase(), "NS")
      } else {
        rootManagerTxId = arweave.utils.bufferTob64Url(hexToBuffer(base36ToBigInt(rootManagerTxId).toString(16)))
        let rootManagerTx = await fetch(`http://${config.arweaveGateway}/${rootManagerTxId}`).then(res => res.json())
        if (!rootManagerTx || typeof rootManagerTx !== "object" || !Array.isArray(rootManagerTx.managers)) {
          throw new Error("No managers found in tx")
        }
        let rootLastZonesTxSearch = await ardb.search("transactions").tags([{ name: "Target-NS-TxID", values: [rootManagerTxId] }]).from(rootManagerTx.managers).sort("HEIGHT_DESC").limit(1).exclude(["anchor"]).find()

        let rootLastZonesTx = rootLastZonesTxSearch.length > 0 ? rootLastZonesTxSearch[0].id : rootManagerTx.recordsTx;
        if (!rootLastZonesTx) {
          throw new Error("No records tx found")
        }
        let rootZoneData = await fetch(`http://${config.arweaveGateway}/${rootLastZonesTx}`).then(res => res.text());
        nsLookUpRes = {
          authority: [],
          answer: wire.fromZone(rootZoneData, question.name).filter(rec => rec.name == question.name)
        };
      }
      if (nsLookUpRes.authority.length == 0) {
        res.answer = nsLookUpRes.answer
        res.authority = []
        res.send()
        return
      }
      let domainNameserverRecords = (nsLookUpRes).authority.filter(record => record && record.data && record.data.ns).map(record => record.data.ns) || (nsLookUpRes).answer.filter(record => record && record.data && record.data.ns).map(record => record.data.ns)
      let managerTxId = domainNameserverRecords.map(record => { return config.zones.some(zone => record.endsWith(zone)) ? record.slice(0, -config.zones.find(zone => record.endsWith(zone)).length) : null }).find(a => a)
      if (!managerTxId) {
        let generalLookup = await subresolver.lookup(question.name.toLowerCase(), question.type)
        res.answer = generalLookup.answer
        res.authority = generalLookup.authority
        res.send()
        return
      }
      managerTxId = arweave.utils.bufferTob64Url(hexToBuffer(base36ToBigInt(managerTxId).toString(16)))
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
const hexToBuffer = (hexString) =>
  Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
function base36ToBigInt(str) {
  return [...str].reduce((acc, curr) => BigInt(parseInt(curr, 36)) + BigInt(36) * acc, 0n);
}