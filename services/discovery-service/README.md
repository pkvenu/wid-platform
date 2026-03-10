# Discovery Service

Auto-discovery service for Workload Identity Platform. Automatically discovers Kubernetes workloads and Docker containers, assigns SPIFFE IDs, and stores them in the database.

## Features

- ✅ Kubernetes workload discovery (Deployments, StatefulSets, DaemonSets, CronJobs)
- ✅ Docker container discovery
- ✅ Automatic SPIFFE ID generation
- ✅ Security score calculation
- ✅ Continuous scanning (every 5 minutes)
- ✅ Manual scan triggering via API
- ✅ Integration with PolicyBuilderV2

## API Endpoints

### Workloads
- `GET /api/v1/workloads` - List all discovered workloads
- `GET /api/v1/workloads/options` - Get dropdown options for PolicyBuilderV2
- `POST /api/v1/workloads/scan` - Trigger manual discovery scan
- `POST /api/v1/workloads/:id/verify` - Verify a workload

### Targets
- `GET /api/v1/targets` - List all targets
- `GET /api/v1/targets/options` - Get dropdown options for PolicyBuilderV2

### Health
- `GET /health` - Health check

## Installation

```bash
npm install
```

## Running Locally

```bash
# Copy environment variables
cp .env.example .env

# Start the service
npm start

# Or with nodemon for development
npm run dev
```

## Running with Docker

```bash
# Build
docker build -t discovery-service .

# Run
docker run -d \
  -p 3003:3003 \
  -e DATABASE_URL=postgresql://wip_user:wip_password@postgres:5432/workload_identity \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v ~/.kube:/root/.kube:ro \
  discovery-service
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3003` | Server port |
| `DATABASE_URL` | `postgresql://wip_user:wip_password@postgres:5432/workload_identity` | PostgreSQL connection string |
| `DISCOVERY_INTERVAL` | `300000` | Discovery scan interval in milliseconds (5 minutes) |
| `SPIRE_TRUST_DOMAIN` | `company.com` | SPIFFE trust domain |

## How It Works

1. **Initial Scan**: Runs on startup
2. **Continuous Scanning**: Automatically scans every 5 minutes (configurable)
3. **Kubernetes Discovery**: 
   - Connects to Kubernetes API
   - Discovers Deployments, StatefulSets, DaemonSets, CronJobs
   - Extracts metadata (namespace, labels, service accounts)
4. **Docker Discovery**:
   - Connects to Docker socket
   - Lists running containers
   - Extracts container metadata
5. **SPIFFE ID Generation**: Creates unique identities
6. **Database Storage**: Saves all discovered workloads
7. **Security Scoring**: Calculates security score based on best practices

## Database Schema

The service uses the `workloads` and `targets` tables. Make sure to run the database migration first:

```bash
docker exec -i wip-postgres psql -U wip_user -d workload_identity < ../database/schemas/04-discovery.sql
```

## Integration with PolicyBuilderV2

The service provides dropdown options for PolicyBuilderV2:

```javascript
// Fetch workload options
const response = await fetch('http://localhost:3003/api/v1/workloads/options');
const { options } = await response.json();

// Fetch target options
const response = await fetch('http://localhost:3003/api/v1/targets/options');
const { options } = await response.json();
```

## Troubleshooting

### Kubernetes Not Detected
- Ensure `~/.kube/config` exists and is accessible
- Or run inside Kubernetes cluster

### Docker Not Detected
- Ensure Docker socket is mounted: `-v /var/run/docker.sock:/var/run/docker.sock`
- Check Docker permissions

### Database Connection Failed
- Verify `DATABASE_URL` is correct
- Ensure PostgreSQL is running
- Check network connectivity

## Development

```bash
# Install dependencies
npm install

# Run with auto-reload
npm run dev

# Test API
curl http://localhost:3003/health
curl http://localhost:3003/api/v1/workloads
```

## License

MIT
