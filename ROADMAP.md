
# Future

## v0 "Accretion Theory"
The version zero major version is an initial development phase focused on
trialing various Python libraries and how they can generate DNSSEC zones.

### v0.1
* Crypto primative tests
 * Generate RSA keys
 * Generate SHA256/384/512 signatures
 * Generate ECDSA keys

### v0.2
* Read/Write PEM/PKCS8 key files

### v0.3
* Read/Write DNSSEC key records
 * DNSKEY
 * DS

### v0.4
* Read/Write DNSSEC signing records
 * RRSIG
 * NSEC3PARAM
 * NSEC3

### v0.5
* Walk and verify 'live' DNSSEC chain

### v0.6
* Read BIND9 zone files
* Verify existing zone files

### v0.7
* Output signed zone files

### v0.8

## v1.0	"Brown dwarf (Class L)"
This major version is focused on making DNSSEC the signing process
practical at a scheduled or manual task level.
This obviously means that zone updates may not be signed for a period of time,
which is suboptimal for frequently changing zones, but acceptable for stable
zone.

## v2.0 "Red dwarf (Class M)"
This major version is focused on making DNSSEC the signing process
more automated with awareness of zone file changes, and the DNS Name Servers
that use the zone files.

## v3.0 "Orange dwarf (Class K)"
This major version will focus on expanding the types DNS Name Servers that can
support autonomous operation.
