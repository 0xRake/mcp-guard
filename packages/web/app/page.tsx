'use client';

import { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, Info, 
  TrendingUp, Server, Activity, BarChart3,
  RefreshCw, Download, Settings
} from 'lucide-react';

interface Stats {
  scansToday: number;
  vulnerabilitiesFound: number;
  criticalIssues: number;
  serversMonitored: number;
  complianceScore: number;
  trends: {
    daily: Array<{
      date: string;
      scans: number;
      vulnerabilities: number;
    }>;
  };
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastScan, setLastScan] = useState<Date>(new Date());

  useEffect(() => {
    // Fetch dashboard stats
    fetchStats();
    const interval = setInterval(fetchStats, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:3001/api/stats');
      const data = await response.json();
      setStats(data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
      setLoading(false);
    }
  };

  const runScan = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:3001/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          config: {
            command: 'node',
            args: ['server.js'],
            metadata: { name: 'test-server' }
          },
          options: { depth: 'quick' }
        })
      });
      const result = await response.json();
      setLastScan(new Date());
      fetchStats();
    } catch (error) {
      console.error('Scan failed:', error);
    }
    setLoading(false);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-600 bg-red-100';
      case 'HIGH': return 'text-orange-600 bg-orange-100';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-100';
      case 'LOW': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getComplianceColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-yellow-600';
    if (score >= 50) return 'text-orange-600';
    return 'text-red-600';
  };

  if (loading && !stats) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <RefreshCw className="h-8 w-8 animate-spin text-blue-600 mx-auto mb-4" />
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">MCP-Guard Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={runScan}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <RefreshCw className="h-4 w-4" />
                <span>Run Scan</span>
              </button>
              <button className="p-2 text-gray-600 hover:text-gray-900">
                <Settings className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Scans Today</p>
                <p className="text-2xl font-bold text-gray-900">{stats?.scansToday || 0}</p>
              </div>
              <Activity className="h-8 w-8 text-blue-600" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Vulnerabilities</p>
                <p className="text-2xl font-bold text-gray-900">{stats?.vulnerabilitiesFound || 0}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-yellow-600" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Critical Issues</p>
                <p className="text-2xl font-bold text-red-600">{stats?.criticalIssues || 0}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-600" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Compliance Score</p>
                <p className={`text-2xl font-bold ${getComplianceColor(stats?.complianceScore || 0)}`}>
                  {stats?.complianceScore || 0}%
                </p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-600" />
            </div>
          </div>
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Vulnerability Trends */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <TrendingUp className="h-5 w-5 mr-2 text-blue-600" />
              Vulnerability Trends
            </h2>
            <div className="h-64 flex items-center justify-center text-gray-500">
              {stats?.trends?.daily && (
                <div className="w-full">
                  <div className="flex justify-between items-end h-48">
                    {stats.trends.daily.map((day, i) => (
                      <div key={i} className="flex-1 mx-1">
                        <div 
                          className="bg-blue-600 rounded-t"
                          style={{ 
                            height: `${(day.vulnerabilities / 200) * 100}%`,
                            minHeight: '10px'
                          }}
                        />
                        <p className="text-xs text-center mt-2">
                          {day.date.split('-').slice(-1)[0]}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Server Status */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Server className="h-5 w-5 mr-2 text-blue-600" />
              Server Status
            </h2>
            <div className="space-y-3">
              {['server-1', 'server-2', 'server-3', 'server-4'].map((server, i) => (
                <div key={server} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                  <div className="flex items-center">
                    <div className={`h-2 w-2 rounded-full mr-3 ${i === 1 ? 'bg-red-500' : 'bg-green-500'}`} />
                    <span className="text-sm font-medium text-gray-900">{server}</span>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded ${i === 1 ? 'bg-red-100 text-red-600' : 'bg-green-100 text-green-600'}`}>
                    {i === 1 ? '3 issues' : 'Secure'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b">
            <h2 className="text-lg font-semibold text-gray-900">Recent Scans</h2>
          </div>
          <div className="p-6">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead>
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Server</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Issues</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {[
                    { server: 'api-server', time: '2 min ago', issues: 5, severity: 'HIGH' },
                    { server: 'web-server', time: '15 min ago', issues: 0, severity: 'SAFE' },
                    { server: 'db-server', time: '1 hour ago', issues: 2, severity: 'MEDIUM' },
                    { server: 'auth-server', time: '3 hours ago', issues: 12, severity: 'CRITICAL' },
                  ].map((scan, i) => (
                    <tr key={i}>
                      <td className="px-4 py-3 text-sm text-gray-900">{scan.server}</td>
                      <td className="px-4 py-3 text-sm text-gray-600">{scan.time}</td>
                      <td className="px-4 py-3 text-sm text-gray-900">{scan.issues}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-1 rounded ${
                          scan.severity === 'CRITICAL' ? 'bg-red-100 text-red-600' :
                          scan.severity === 'HIGH' ? 'bg-orange-100 text-orange-600' :
                          scan.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-600' :
                          'bg-green-100 text-green-600'
                        }`}>
                          {scan.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Last Scan Info */}
        <div className="mt-8 text-center text-sm text-gray-500">
          Last scan: {lastScan.toLocaleString()}
        </div>
      </main>
    </div>
  );
}