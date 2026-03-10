// =============================================================================
// Scanner Registry - Auto-discovers and manages all scanners
// =============================================================================

const fs = require('fs');
const path = require('path');

class ScannerRegistry {
  constructor() {
    this.scanners = new Map();
    this.scannersDir = path.join(__dirname, '..');
  }

  /**
   * Auto-discover and register all scanners
   */
  async discoverScanners() {
    console.log('🔍 Discovering available scanners...\n');
    
    // Scan subdirectories — now includes credentials
    const categories = ['cloud', 'container', 'credentials', 'on-prem'];
    
    for (const category of categories) {
      const categoryPath = path.join(this.scannersDir, category);
      
      if (!fs.existsSync(categoryPath)) {
        continue;
      }
      
      const files = fs.readdirSync(categoryPath)
        .filter(f => f.endsWith('.js') && f !== 'index.js');
      
      for (const file of files) {
        try {
          const scannerPath = path.join(categoryPath, file);
          const ScannerClass = require(scannerPath);
          
          // Skip if not a valid scanner class
          if (typeof ScannerClass !== 'function') continue;
          
          const scannerName = path.basename(file, '.js');
          this.scanners.set(scannerName, {
            name: scannerName,
            category,
            class: ScannerClass,
            path: scannerPath
          });
          
          console.log(`  ✔ Registered scanner: ${scannerName} (${category})`);
        } catch (error) {
          console.error(`  ✗ Failed to load scanner ${file}:`, error.message);
        }
      }
    }
    
    console.log(`\n📊 Total scanners registered: ${this.scanners.size}\n`);
    return this.scanners;
  }

  /**
   * Get all registered scanners
   */
  getScanners() {
    return Array.from(this.scanners.values());
  }

  /**
   * Get scanner by name
   */
  getScanner(name) {
    return this.scanners.get(name);
  }

  /**
   * Get scanners by category
   */
  getScannersByCategory(category) {
    return Array.from(this.scanners.values())
      .filter(s => s.category === category);
  }

  /**
   * Initialize scanner instances with config
   */
  async initializeScanners(config = {}) {
    const instances = [];
    this.allScannerStatuses = [];

    for (const [name, scanner] of this.scanners) {
      const entry = { name, category: scanner.category, status: 'unknown', enabled: false };
      try {
        const scannerConfig = config[name] || {};
        const instance = new scanner.class(scannerConfig);

        // Validate scanner (some scanners don't extend BaseScanner)
        const hasValidate = typeof instance.validate === 'function';
        const hasGetMetadata = typeof instance.getMetadata === 'function';
        const isValid = hasValidate ? await instance.validate() : true;
        const isEnabled = instance.enabled !== false;

        if (hasGetMetadata) entry.metadata = instance.getMetadata();

        // Capture required credentials info for the UI
        if (typeof instance.getRequiredCredentials === 'function') {
          entry.requiredCredentials = instance.getRequiredCredentials();
        }

        if (isValid && isEnabled) {
          instances.push(instance);
          entry.status = 'active';
          entry.enabled = true;
          console.log(`  ✔ Initialized: ${name} (${scanner.category})`);
        } else {
          // Use scanner's own reason if provided, else infer from state
          const scannerReason = instance.disabledReason;
          if (!isEnabled && scannerReason) {
            entry.status = 'disabled';
            entry.reason = scannerReason;
          } else if (!isEnabled) {
            entry.status = 'disabled';
            entry.reason = 'No credentials configured';
          } else {
            entry.status = 'invalid_config';
            entry.reason = 'Validation failed — credentials may be expired or incorrect';
          }
          console.log(`  ⊘ Skipped: ${name} (${entry.status}: ${entry.reason})`);
        }
      } catch (error) {
        entry.status = 'error';
        entry.reason = error.message;
        console.error(`  ✗ Failed to initialize ${name}:`, error.message);
      }
      this.allScannerStatuses.push(entry);
    }

    return instances;
  }

  /**
   * Get status of all registered scanners (active + inactive)
   */
  getAllScannerStatuses() {
    return this.allScannerStatuses || [];
  }
}

module.exports = ScannerRegistry;