# DMARC Analyzer

A TypeScript/Node.js application for analyzing DMARC aggregate reports with issue detection and remediation guidance.

## Features

- **DMARC Report Processing**: Parses XML DMARC aggregate reports (both `.xml` and `.xml.gz` formats)
- **Issue Detection**: Identifies authentication issues including:
  - DKIM alignment failures
  - SPF soft fails and hard fails
  - SPF configuration errors (permerror, temperror)
  - DKIM verification failures
  - Non-enforcing DMARC policies
  - Third-party sender detection
- **DNS Integration**: Fetches current SPF, DMARC, and DKIM records for domains
- **Remediation Guidance**: Provides step-by-step instructions for fixing identified issues
- **Analytics**: Calculates pass rates, tracks trends, and generates statistics

## Installation

```bash
npm install
```

## Usage

### Development

```bash
npm run dev
```

### Production

```bash
npm run build
npm start
```

The server runs on `http://localhost:3000` by default.

## Adding DMARC Reports

Place your DMARC aggregate report XML files (or `.gz` compressed files) in the `dmarc-reports/` directory, then use the refresh endpoint to process them.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/data` | GET | Get all domains with analysis |
| `/api/domain/:domain` | GET | Get analysis for a specific domain |
| `/api/refresh` | POST | Process new DMARC reports |
| `/api/dns/:domain` | GET | Fetch DNS records for a domain |
| `/api/dns/:domain/refresh` | POST | Force refresh DNS records |

## Project Structure

```
dmarc-analyzer/
├── src/
│   ├── server.ts       # Express server with REST APIs
│   ├── parser.ts       # XML report parsing
│   ├── analyzer.ts     # Issue detection and statistics
│   ├── dns-lookup.ts   # DNS record fetching
│   ├── enricher.ts     # Issue enrichment with DNS context
│   ├── storage.ts      # Data persistence
│   └── types.ts        # TypeScript interfaces
├── public/             # Frontend files
├── dmarc-reports/      # Input directory for DMARC reports
└── dmarc-data.json     # Persistent data storage
```

## Tech Stack

- **Runtime**: Node.js
- **Language**: TypeScript
- **Web Framework**: Express.js
- **XML Parsing**: xml2js

## License

ISC
