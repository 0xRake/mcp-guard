#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'fs';
import chalk from 'chalk';

interface Task {
  id: string;
  name: string;
  status: 'pending' | 'in_progress' | 'completed';
  progress: number; // 0-100
  estimatedHours: number;
  actualHours?: number;
}

interface Package {
  name: string;
  progress: number;
  tasks: Task[];
}

class ProgressTracker {
  private progress: {
    overall: number;
    packages: Package[];
    mvpProgress: number;
    fullProgress: number;
    timeSpent: number;
    timeRemaining: number;
  };

  constructor() {
    this.load();
  }

  private load() {
    try {
      const data = readFileSync('.mcp-guard-build/progress.json', 'utf-8');
      this.progress = JSON.parse(data);
    } catch {
      this.initialize();
    }
  }

  private initialize() {
    this.progress = {
      overall: 15,
      mvpProgress: 20,
      fullProgress: 8,
      timeSpent: 1.5,
      timeRemaining: 20,
      packages: [
        {
          name: '@mcp-guard/core',
          progress: 25,
          tasks: [
            { id: 'setup', name: 'Package Setup', status: 'completed', progress: 100, estimatedHours: 0.25 },
            { id: 'types', name: 'Type Definitions', status: 'completed', progress: 100, estimatedHours: 0.25 },
            { id: 'api-scanner', name: 'API Key Scanner', status: 'in_progress', progress: 20, estimatedHours: 1 },
            { id: 'auth-scanner', name: 'Auth Scanner', status: 'pending', progress: 0, estimatedHours: 0.5 },
            // ... more tasks
          ]
        },
        // ... more packages
      ]
    };
  }

  private createBar(progress: number, width = 25): string {
    const filled = Math.floor((progress / 100) * width);
    const empty = width - filled;
    const bar = '█'.repeat(filled) + '░'.repeat(empty);
    
    if (progress === 100) return chalk.green(bar);
    if (progress >= 75) return chalk.blue(bar);
    if (progress >= 50) return chalk.yellow(bar);
    if (progress >= 25) return chalk.magenta(bar);
    return chalk.red(bar);
  }

  public display() {
    console.clear();
    console.log(chalk.bold.cyan('\n🚀 MCP-Guard Progress Dashboard\n'));
    console.log('═'.repeat(60));
    
    // Overall Progress
    console.log(chalk.bold('\n📊 Overall Project Progress'));
    console.log(this.createBar(this.progress.overall, 40), chalk.bold(`${this.progress.overall}%`));
    
    // MVP vs Full Build
    console.log(chalk.bold('\n🎯 Milestone Progress'));
    console.log('MVP  (2-3h):', this.createBar(this.progress.mvpProgress, 30), `${this.progress.mvpProgress}%`);
    console.log('Full (18h) :', this.createBar(this.progress.fullProgress, 30), `${this.progress.fullProgress}%`);
    
    // Time Tracking
    console.log(chalk.bold('\n⏱️  Time Tracking'));
    console.log(`Time Spent: ${chalk.green(this.progress.timeSpent + 'h')}`);
    console.log(`Remaining: ${chalk.yellow(this.progress.timeRemaining + 'h')}`);
    
    // Package Progress
    console.log(chalk.bold('\n📦 Package Progress'));
    this.progress.packages.forEach(pkg => {
      console.log(`\n${pkg.name}`);
      console.log(this.createBar(pkg.progress, 35), `${pkg.progress}%`);
      
      pkg.tasks.slice(0, 3).forEach(task => {
        const icon = task.status === 'completed' ? '✅' : 
                    task.status === 'in_progress' ? '🔄' : '⏳';
        console.log(`  ${icon} ${task.name.padEnd(25)} ${this.createBar(task.progress, 15)} ${task.progress}%`);
      });
    });
    
    console.log('\n' + '═'.repeat(60));
  }

  public update(packageName: string, taskId: string, progress: number) {
    const pkg = this.progress.packages.find(p => p.name === packageName);
    if (pkg) {
      const task = pkg.tasks.find(t => t.id === taskId);
      if (task) {
        task.progress = progress;
        if (progress === 100) task.status = 'completed';
        else if (progress > 0) task.status = 'in_progress';
        
        // Recalculate package progress
        pkg.progress = Math.round(
          pkg.tasks.reduce((sum, t) => sum + t.progress, 0) / pkg.tasks.length
        );
        
        // Recalculate overall progress
        this.progress.overall = Math.round(
          this.progress.packages.reduce((sum, p) => sum + p.progress, 0) / 
          this.progress.packages.length
        );
        
        this.save();
      }
    }
  }

  private save() {
    writeFileSync('.mcp-guard-build/progress.json', JSON.stringify(this.progress, null, 2));
  }
}

// Run the tracker
const tracker = new ProgressTracker();
const command = process.argv[2];

if (command === 'update') {
  const [pkg, task, progress] = process.argv.slice(3);
  tracker.update(pkg, task, parseInt(progress));
}

tracker.display();
