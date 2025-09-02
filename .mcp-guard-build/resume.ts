#!/usr/bin/env node

/**
 * MCP-Guard Build Resume Script
 * This script allows us to continue the build from where we left off
 */

import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const MEMORY_FILE = join(process.cwd(), '.mcp-guard-build', 'build-memory.json');

class BuildResume {
  private memory: any;

  constructor() {
    this.loadMemory();
  }

  loadMemory() {
    try {
      const data = readFileSync(MEMORY_FILE, 'utf-8');
      this.memory = JSON.parse(data);
      console.log('✅ Build memory loaded successfully');
      console.log(`📍 Current Phase: ${this.memory.buildProgress.currentPhase}`);
      console.log(`📍 Current Step: ${this.memory.buildProgress.currentStep}`);
    } catch (error) {
      console.error('❌ Failed to load build memory:', error);
      process.exit(1);
    }
  }

  saveMemory() {
    try {
      writeFileSync(MEMORY_FILE, JSON.stringify(this.memory, null, 2));
      console.log('✅ Build memory saved');
    } catch (error) {
      console.error('❌ Failed to save build memory:', error);
    }
  }

  updateProgress(updates: any) {
    Object.assign(this.memory.buildProgress, updates);
    this.memory.session.lastUpdated = new Date().toISOString();
    this.saveMemory();
  }

  addCompletedFile(filepath: string) {
    if (!this.memory.buildProgress.filesCreated.includes(filepath)) {
      this.memory.buildProgress.filesCreated.push(filepath);
      this.saveMemory();
    }
  }

  getCurrentContext() {
    return {
      phase: this.memory.buildProgress.currentPhase,
      step: this.memory.buildProgress.currentStep,
      nextSteps: this.memory.buildProgress.nextSteps,
      config: this.memory.configuration
    };
  }

  printStatus() {
    console.log('\n📊 MCP-Guard Build Status');
    console.log('========================');
    console.log(`Project: ${this.memory.project.name} v${this.memory.project.version}`);
    console.log(`Location: ${this.memory.project.rootPath}`);
    console.log('\n📦 Packages:');
    this.memory.architecture.packages.forEach((pkg: any) => {
      const icon = pkg.status === 'completed' ? '✅' : 
                   pkg.status === 'in_progress' ? '🔄' : '⏳';
      console.log(`  ${icon} ${pkg.name} - ${pkg.status}`);
    });
    console.log('\n✅ Completed Steps:');
    this.memory.buildProgress.completedSteps.forEach((step: string) => {
      console.log(`  • ${step}`);
    });
    console.log('\n📝 Next Steps:');
    this.memory.buildProgress.nextSteps.slice(0, 3).forEach((step: string) => {
      console.log(`  • ${step}`);
    });
    console.log('\n📁 Files Created:', this.memory.buildProgress.filesCreated.length);
  }
}

// Auto-run when imported
if (require.main === module) {
  const resume = new BuildResume();
  resume.printStatus();
}

export default BuildResume;
