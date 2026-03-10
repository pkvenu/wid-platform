// =============================================================================
// Audit Service - Centralized Logging and Analytics
// Port: 3003
// =============================================================================

const express = require('express');
const { Client } = require('pg');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3003;
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://wip_user:wip_password@localhost:5432/workload_identity';

let dbClient = null;

// =============================================================================
// Initialize Database Connection
// =============================================================================
async function initDatabase() {
  try {
    dbClient = new Client({ connectionString: DATABASE_URL });
    await dbClient.connect();
    console.log('✅ Connected to database');
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    console.log('⚠️  Running without database (logs to console only)');
  }
}

// =============================================================================
// Log Event Endpoint
// =============================================================================
app.post('/v1/log', async (req, res) => {
  const {
    event_type,
    workload_id,
    target,
    result,
    metadata
  } = req.body;
  
  console.log(`\n📝 Audit log: ${event_type}`);
  console.log(`  Workload: ${workload_id}`);
  console.log(`  Target: ${target}`);
  console.log(`  Result: ${result}`);
  
  try {
    if (dbClient) {
      await dbClient.query(
        `INSERT INTO audit_log 
         (event_type, workload_id, target, result, metadata, created_at) 
         VALUES ($1, $2, $3, $4, $5, NOW())`,
        [event_type, workload_id, target, result, JSON.stringify(metadata)]
      );
    }
    
    res.json({ success: true, logged: true });
    
  } catch (error) {
    console.error('❌ Failed to log:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// =============================================================================
// Query Logs Endpoint
// =============================================================================
app.get('/v1/logs', async (req, res) => {
  const { 
    event_type, 
    workload_id, 
    limit = 100,
    since 
  } = req.query;
  
  try {
    if (!dbClient) {
      return res.status(503).json({ 
        error: 'database_unavailable',
        message: 'Database not connected'
      });
    }
    
    let query = 'SELECT * FROM audit_log WHERE 1=1';
    const params = [];
    let paramCount = 1;
    
    if (event_type) {
      query += ` AND event_type = $${paramCount}`;
      params.push(event_type);
      paramCount++;
    }
    
    if (workload_id) {
      query += ` AND workload_id = $${paramCount}`;
      params.push(workload_id);
      paramCount++;
    }
    
    if (since) {
      query += ` AND created_at > $${paramCount}`;
      params.push(since);
      paramCount++;
    }
    
    query += ` ORDER BY created_at DESC LIMIT $${paramCount}`;
    params.push(limit);
    
    const result = await dbClient.query(query, params);
    
    res.json({
      count: result.rows.length,
      logs: result.rows
    });
    
  } catch (error) {
    console.error('❌ Query failed:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// Statistics Endpoint
// =============================================================================
app.get('/v1/stats', async (req, res) => {
  try {
    if (!dbClient) {
      return res.json({
        message: 'Database not connected',
        stats: {
          total_events: 0,
          denied_events: 0,
          unique_workloads: 0
        }
      });
    }
    
    const stats = await dbClient.query(`
      SELECT 
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE result = 'denied') as denied_events,
        COUNT(DISTINCT workload_id) as unique_workloads,
        MAX(created_at) as last_event
      FROM audit_log
      WHERE created_at > NOW() - INTERVAL '24 hours'
    `);
    
    res.json({
      period: 'last_24_hours',
      stats: stats.rows[0]
    });
    
  } catch (error) {
    console.error('❌ Stats query failed:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// Health Check
// =============================================================================
app.get('/health', async (req, res) => {
  let dbHealthy = false;
  
  if (dbClient) {
    try {
      await dbClient.query('SELECT 1');
      dbHealthy = true;
    } catch (error) {
      dbHealthy = false;
    }
  }
  
  res.json({
    service: 'audit-service',
    status: dbHealthy ? 'healthy' : 'degraded',
    database_connected: dbHealthy
  });
});

// =============================================================================
// Start Server
// =============================================================================
async function start() {
  await initDatabase();
  
  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║  Audit Service - Centralized Logging                      ║
║  Port: ${PORT}                                                 ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

Endpoints:
  POST /v1/log     → Log audit event
  GET  /v1/logs    → Query audit logs
  GET  /v1/stats   → Get statistics
  GET  /health     → Health check

Configuration:
  Database: ${dbClient ? 'Connected ✅' : 'Not connected ⚠️'}

Ready! 🚀
`);
  });
}

start();
