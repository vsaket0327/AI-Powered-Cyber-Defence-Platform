
import { useEffect, useState, type FormEvent } from "react";
import {
  Activity,
  ShieldCheck,
  Database,
  Server,
  Search,
  AlertCircle,
  LoaderCircle,
  BrainCircuit,
  ClipboardList,
} from "lucide-react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

import {
  apiFetch,
  getToken,
  getUser,
  login,
  logout,
  getAdminUsers,
  createAdminUser,
  updateAdminUser,
  deleteAdminUser,
  type AuthUser,
  type AdminUser,
  type UserRole,
    getAlerts,
  updateAlert,
  convertAlertToIncident,
  type SecurityAlert,
  type AlertSeverity,
  type AlertStatus,
  analyzePcap,
type NetworkFlow,
type PcapAnalysisResponse,
getNetworkAnomalies,
detectNetworkAnomalies,
type NetworkAnomaly,
type AnomalyDetectionResponse,
} from "./auth";
type Health = {
  status: string;
  service: string;
};

type IndicatorType = "ip" | "domain" | "url" | "hash";


type ThreatIntelligence = {
  available: boolean;
  source: string;
  verdict?: string;
  risk_level?: string;
  reputation?: number;
  analysis_stats?: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
  };
  error?: string;
};

type AnalysisResult = {
  indicator_type: string;
  indicator: string;
  format_valid: boolean;
  risk_level: string;
  verdict: string;
  evidence?: unknown;
  details?: unknown;
  recommendation?: string;
  threat_intelligence?: ThreatIntelligence;
};
type AuditLog = {
  id: number;
  user_id: number | null;
  username: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown>;
  ip_address: string | null;
  created_at: string | null;
};

type AuditLogsResponse = {
  count: number;
  items: AuditLog[];
};

type HistoryItem = {
  id: number;
  indicator_type: string;
  indicator: string;
  format_valid: boolean;
  risk_level: string;
  verdict: string;
  created_at: string;
};

type HistoryResponse = {
  count: number;
  items: HistoryItem[];
};
type IncidentStatus =
  | "open"
  | "investigating"
  | "resolved"
  | "closed";

type IncidentSeverity =
  | "low"
  | "medium"
  | "high"
  | "critical";


type Incident = {
  id: number;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  indicator_type: IndicatorType | null;
  indicator: string | null;
  created_at: string;
  updated_at: string;
  evidence: Record<string, unknown>;

  assigned_to: string | null;
  resolution_summary: string | null;
  root_cause: string | null;
  resolved_at: string | null;
  closed_at: string | null;
};
type AIReportData = {
  executive_summary: string;
  threat_category: string;
  severity: "low" | "medium" | "high" | "critical" | "unknown";
  confidence: "low" | "medium" | "high";
  key_findings: string[];
  evidence_assessment: string[];
  recommended_actions: string[];
  limitations: string[];
};

type AIReportHistoryItem = {
  report_id: number;
  user_id: number | null;
  incident_id: number | null;
  alert_id: number | null;
  model_name: string;
  created_at: string;
  severity: string;
  threat_category: string;
  executive_summary: string;
};

type AIReportHistoryResponse = {
  total: number;
  skip: number;
  limit: number;
  items: AIReportHistoryItem[];
};

type AIReportDetail = {
  report_id: number;
  user_id: number | null;
  incident_id: number | null;
  alert_id: number | null;
  model_name: string;
  created_at: string;
  evidence_snapshot: Record<string, unknown>;
  report: AIReportData;
};


type IncidentResponse = {
  count: number;
  items: Incident[];
};
type IncidentActivity = {
  id: number;
  incident_id: number;
  action: string;
  description: string;
  actor: string;
  created_at: string;
};

type IncidentNote = {
  id: number;
  incident_id: number;
  note: string;
  author: string;
  created_at: string;
};

type InvestigationResponse<T> = {
  count: number;
  items: T[];
};
const API_BASE = "https://ai-powered-cyber-defence-platform.onrender.com";

const fieldStyle = {
  width: "100%",
  padding: "12px",
  borderRadius: "8px",
  border: "1px solid #334155",
  background: "#0f172a",
  color: "#e2e8f0",
  fontSize: "14px",
  boxSizing: "border-box" as const,
};

function formatValue(value: unknown): string {
  if (value === undefined || value === null) return "No information provided.";
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

export default function App() {
    const [currentUser, setCurrentUser] = useState<AuthUser | null>(
    () => getUser()
  );
const [activePage, setActivePage] = useState<
  | "overview"
  | "users"
  | "alerts"
  | "network"
  | "anomalies"
  | "ai-analysis"
  | "audit-logs"
>("overview");
const [aiReportHistory, setAiReportHistory] = useState<AIReportHistoryItem[]>([]);
const [aiHistoryLoading, setAiHistoryLoading] = useState(false);
const [aiAnalysisError, setAiAnalysisError] = useState("");
const [aiSelectedIncidentId, setAiSelectedIncidentId] = useState("");
const [aiGenerating, setAiGenerating] = useState(false);
const [selectedAIReport, setSelectedAIReport] = useState<AIReportDetail | null>(null);
const [aiDetailLoading, setAiDetailLoading] = useState(false);
const [pcapFile, setPcapFile] = useState<File | null>(null);
const [networkAnalysis, setNetworkAnalysis] =
  useState<PcapAnalysisResponse | null>(null);

const [networkLoading, setNetworkLoading] = useState(false);
const [networkError, setNetworkError] = useState("");

const [networkSearch, setNetworkSearch] = useState("");
const [networkProtocolFilter, setNetworkProtocolFilter] =
  useState<"all" | "TCP" | "UDP">("all");
// ===============================
// ALERT MANAGEMENT STATE
// ===============================

const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
const [alertsLoading, setAlertsLoading] = useState(false);
const [alertsError, setAlertsError] = useState("");

const [alertSearch, setAlertSearch] = useState("");
const [alertSeverityFilter, setAlertSeverityFilter] = useState<
  AlertSeverity | ""
>("");
const [alertStatusFilter, setAlertStatusFilter] = useState<
  AlertStatus | ""
>("");
const [networkAnomalies, setNetworkAnomalies] = useState<NetworkAnomaly[]>([]);
const [anomalyHistoryLoading, setAnomalyHistoryLoading] = useState(false);
const [anomalyDetectionLoading, setAnomalyDetectionLoading] = useState(false);
const [anomalyError, setAnomalyError] = useState("");
const [anomalyDetectionResult, setAnomalyDetectionResult] =
  useState<AnomalyDetectionResponse | null>(null);
  const [authChecking, setAuthChecking] = useState<boolean>(
    () => Boolean(getToken())
  );

  const [loginIdentifier, setLoginIdentifier] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);

// Load all registered users
async function loadAdminUsers() {
  setUsersLoading(true);
  setUsersError("");

  try {
    const data = await getAdminUsers();
    setAdminUsers(data.items);
  } catch (error) {
    setUsersError(
      error instanceof Error
        ? error.message
        : "Unable to load users."
    );
  } finally {
    setUsersLoading(false);
  }
}

// Create a new user
async function handleCreateUser(
  event: FormEvent<HTMLFormElement>
) {
  event.preventDefault();

  setUserSaving(true);
  setUsersError("");
  setUsersSuccess("");

  try {
    await createAdminUser({
      username: newUsername.trim(),
      email: newEmail.trim(),
      password: newPassword,
      role: newUserRole,
    });

    setUsersSuccess("User created successfully.");

    setNewUsername("");
    setNewEmail("");
    setNewPassword("");
    setNewUserRole("analyst");
    setShowCreateUser(false);

    await loadAdminUsers();
  } catch (error) {
    setUsersError(
      error instanceof Error
        ? error.message
        : "Unable to create user."
    );
  } finally {
    setUserSaving(false);
  }
}

// Update a user's role
async function handleRoleUpdate(
  userId: number,
  role: UserRole
) {
  setEditingUserId(userId);
  setUsersError("");
  setUsersSuccess("");

  try {
    await updateAdminUser(userId, { role });

    setUsersSuccess("User role updated successfully.");
    await loadAdminUsers();
  } catch (error) {
    setUsersError(
      error instanceof Error
        ? error.message
        : "Unable to update user role."
    );
  } finally {
    setEditingUserId(null);
  }
}

// Activate or deactivate a user
async function handleUserStatus(
  userId: number,
  isActive: boolean
) {
  setEditingUserId(userId);
  setUsersError("");
  setUsersSuccess("");

  try {
    await updateAdminUser(userId, {
      is_active: isActive,
    });

    setUsersSuccess(
      isActive
        ? "User account activated."
        : "User account deactivated."
    );

    await loadAdminUsers();
  } catch (error) {
    setUsersError(
      error instanceof Error
        ? error.message
        : "Unable to update account status."
    );
  } finally {
    setEditingUserId(null);
  }
}

// Delete a user
async function handleDeleteUser(userId: number) {
  const confirmed = window.confirm(
    "Are you sure you want to permanently delete this user?"
  );

  if (!confirmed) return;

  setUsersError("");
  setUsersSuccess("");

  try {
    await deleteAdminUser(userId);

    setUsersSuccess("User deleted successfully.");
    await loadAdminUsers();
  } catch (error) {
    setUsersError(
      error instanceof Error
        ? error.message
        : "Unable to delete user."
    );
  }
}

    useEffect(() => {
    const token = getToken();

    if (!token) {
      setAuthChecking(false);
      return;
    }

    apiFetch("http://ai-powered-cyber-defence-platform.onrender.com/api/v1/auth/me")
      .then(async (response) => {
        if (!response.ok) {
          throw new Error("Session expired. Please log in again.");
        }

        const user = await response.json();
        setCurrentUser(user);
      })
      .catch(() => {
        logout();
        setCurrentUser(null);
      })
      .finally(() => {
        setAuthChecking(false);
      });
  }, []);
    const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    setLoginError("");
    setLoginLoading(true);

    try {
      const result = await login(loginIdentifier, loginPassword);

      setCurrentUser(result.user);
      setLoginPassword("");
    } catch (error) {
      setLoginError(
        error instanceof Error ? error.message : "Login failed."
      );
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = () => {
    logout();
    setCurrentUser(null);
    setLoginIdentifier("");
    setLoginPassword("");
    setLoginError("");
  };
  const isAdmin = currentUser?.role === "admin";

const isAnalyst = currentUser?.role === "analyst";

const isViewer = currentUser?.role === "viewer";

const canAnalyze = isAdmin || isAnalyst;

const canManageIncidents = isAdmin || isAnalyst;

const canDeleteIncidents = isAdmin;
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState("");

  const [indicatorType, setIndicatorType] =
    useState<IndicatorType>("ip");
  const [indicator, setIndicator] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [analysisError, setAnalysisError] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
const [auditLogsLoading, setAuditLogsLoading] = useState(false);
const [auditLogsError, setAuditLogsError] = useState("");
const [auditLogActionFilter, setAuditLogActionFilter] = useState("");
const [reportGenerating, setReportGenerating] = useState(false);
const [reportError, setReportError] = useState("");
  // Admin User Management
const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
const [usersLoading, setUsersLoading] = useState(false);
const [usersError, setUsersError] = useState("");
const [usersSuccess, setUsersSuccess] = useState("");

const [userSearch, setUserSearch] = useState("");
const [userRoleFilter, setUserRoleFilter] = useState("all");

const [showCreateUser, setShowCreateUser] = useState(false);
const [newUsername, setNewUsername] = useState("");
const [newEmail, setNewEmail] = useState("");
const [newPassword, setNewPassword] = useState("");
const [newUserRole, setNewUserRole] = useState<UserRole>("analyst");

const [userSaving, setUserSaving] = useState(false);
const [editingUserId, setEditingUserId] = useState<number | null>(null);
  const [selectedIncident, setSelectedIncident] =
  useState<Incident | null>(null);
const incidentSeverityCounts = {
  critical: incidents.filter((item) => item.severity === "critical").length,
  high: incidents.filter((item) => item.severity === "high").length,
  medium: incidents.filter((item) => item.severity === "medium").length,
  low: incidents.filter((item) => item.severity === "low").length,
};
const incidentSeverityChartData = [
  { severity: "Critical", count: incidentSeverityCounts.critical },
  { severity: "High", count: incidentSeverityCounts.high },
  { severity: "Medium", count: incidentSeverityCounts.medium },
  { severity: "Low", count: incidentSeverityCounts.low },
];
const alertSeverityCounts = {
  critical: alerts.filter((item) => item.severity === "critical").length,
  high: alerts.filter((item) => item.severity === "high").length,
  medium: alerts.filter((item) => item.severity === "medium").length,
  low: alerts.filter((item) => item.severity === "low").length,
};
const alertSeverityChartData = [
  { severity: "Critical", count: alertSeverityCounts.critical },
  { severity: "High", count: alertSeverityCounts.high },
  { severity: "Medium", count: alertSeverityCounts.medium },
  { severity: "Low", count: alertSeverityCounts.low },
];

const threatIntelligenceChartData = [
  {
    name: "Malicious",
    value: result?.threat_intelligence?.analysis_stats?.malicious ?? 0,
  },
  {
    name: "Suspicious",
    value: result?.threat_intelligence?.analysis_stats?.suspicious ?? 0,
  },
  {
    name: "Harmless",
    value: result?.threat_intelligence?.analysis_stats?.harmless ?? 0,
  },
  {
    name: "Undetected",
    value: result?.threat_intelligence?.analysis_stats?.undetected ?? 0,
  },
];

const incidentStatusCounts = {
  open: incidents.filter((item) => item.status === "open").length,
  investigating: incidents.filter((item) => item.status === "investigating").length,
  resolved: incidents.filter((item) => item.status === "resolved").length,
  closed: incidents.filter((item) => item.status === "closed").length,
};
const incidentStatusChartData = [
  { status: "Open", count: incidentStatusCounts.open },
  { status: "Investigating", count: incidentStatusCounts.investigating },
  { status: "Resolved", count: incidentStatusCounts.resolved },
  { status: "Closed", count: incidentStatusCounts.closed },
];
const [incidentActivities, setIncidentActivities] =
  useState<IncidentActivity[]>([]);

const [incidentNotes, setIncidentNotes] =
  useState<IncidentNote[]>([]);

const [investigationLoading, setInvestigationLoading] =
  useState(false);

const [investigationError, setInvestigationError] =
  useState("");

const [newNote, setNewNote] = useState("");
const [noteSaving, setNoteSaving] = useState(false);
const [assignedTo, setAssignedTo] = useState("");
const [rootCause, setRootCause] = useState("");
const [resolutionSummary, setResolutionSummary] = useState("");
const [incidentUpdateSaving, setIncidentUpdateSaving] = useState(false);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsError, setIncidentsError] = useState("");

  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [incidentSeverity, setIncidentSeverity] =
  useState<IncidentSeverity>("medium");
  const [incidentIndicatorType, setIncidentIndicatorType] =
  useState<IndicatorType>("domain");
  const [incidentIndicator, setIncidentIndicator] = useState("");
  const [incidentFormError, setIncidentFormError] = useState("");
  const [incidentSaving, setIncidentSaving] = useState(false);

  const [incidentStatusFilter, setIncidentStatusFilter] =
  useState("all");
  const [incidentSeverityFilter, setIncidentSeverityFilter] =
  useState("all");


  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then((response) => {
        if (!response.ok) throw new Error("API error");
        return response.json() as Promise<Health>;
      })
      .then(setHealth)
      .catch(() =>
        setError("API unavailable — start FastAPI on port 8000.")
      );
  }, []);
  useEffect(() => {
  if (activePage === "ai-analysis") {
    loadAIReportHistory();
  }
}, [activePage]);

async function loadHistory() {
  setHistoryLoading(true);
  setHistoryError("");

  try {
    const response = await apiFetch(
      `${API_BASE}/api/v1/indicators/history?limit=20`
    );

    if (!response.ok) {
      throw new Error(`History request failed: ${response.status}`);
    }

    const data: HistoryResponse = await response.json();
    setHistory(data.items);
  } catch (err) {
    setHistoryError(
      err instanceof Error
        ? err.message
        : "Unable to load analysis history."
    );
  } finally {
    setHistoryLoading(false);
  }
}
async function loadIncidents() {
  setIncidentsLoading(true);
  setIncidentsError("");

  try {
    const params = new URLSearchParams();

    if (incidentStatusFilter !== "all") {
      params.set("status", incidentStatusFilter);
    }

    if (incidentSeverityFilter !== "all") {
      params.set("severity", incidentSeverityFilter);
    }

    params.set("limit", "100");

    const response = await apiFetch(
      `${API_BASE}/api/v1/incidents?${params.toString()}`
    );

    if (!response.ok) {
      throw new Error(`Incident request failed: ${response.status}`);
    }

    const data: IncidentResponse = await response.json();
    setIncidents(data.items);
  } catch (err) {
    setIncidentsError(
      err instanceof Error
        ? err.message
        : "Unable to load incidents."
    );
  } finally {
    setIncidentsLoading(false);
  }
}
const loadAIReportHistory = async () => {
  setAiHistoryLoading(true);
  setAiAnalysisError("");

  try {
    const response = await apiFetch(
      `${API_BASE}/api/v1/ai-analysis/reports?skip=0&limit=20`
    );

    if (!response.ok) {
      throw new Error("Failed to load AI report history.");
    }

    const data: AIReportHistoryResponse = await response.json();
    setAiReportHistory(data.items);
  } catch (error) {
    setAiAnalysisError(
      error instanceof Error ? error.message : "Unable to load AI reports."
    );
  } finally {
    setAiHistoryLoading(false);
  }
};
const generateAIReport = async () => {
  if (!aiSelectedIncidentId) {
    setAiAnalysisError("Please select an incident first.");
    return;
  }

  setAiGenerating(true);
  setAiAnalysisError("");
  setSelectedAIReport(null);

  try {
    const response = await apiFetch(
      `${API_BASE}/api/v1/ai-analysis/incidents/${aiSelectedIncidentId}`,
      { method: "POST" }
    );

    if (!response.ok) {
      throw new Error("AI report generation failed.");
    }

    const data = await response.json();

    await loadAIReportHistory();

    setAiAnalysisError("");
    return data;
  } catch (error) {
    setAiAnalysisError(
      error instanceof Error ? error.message : "Unable to generate AI report."
    );
  } finally {
    setAiGenerating(false);
  }
};
const loadAIReportDetail = async (reportId: number) => {
  setAiDetailLoading(true);
  setAiAnalysisError("");
  setSelectedAIReport(null);

  try {
    const response = await apiFetch(
      `${API_BASE}/api/v1/ai-analysis/reports/${reportId}`
    );

    if (!response.ok) {
      throw new Error("Failed to load AI report details.");
    }

    const data: AIReportDetail = await response.json();
    setSelectedAIReport(data);
  } catch (error) {
    setAiAnalysisError(
      error instanceof Error ? error.message : "Unable to load report details."
    );
  } finally {
    setAiDetailLoading(false);
  }
};
// ===============================
// LOAD SECURITY ALERTS
// ===============================

const loadAlerts = async () => {
  setAlertsLoading(true);
  setAlertsError("");

  try {
    const response = await getAlerts({
      search: alertSearch,
      severity: alertSeverityFilter || undefined,
      status: alertStatusFilter || undefined,
      limit: 100,
    });

    setAlerts(response.items);
  } catch (error) {
    setAlertsError(
      error instanceof Error
        ? error.message
        : "Failed to load security alerts."
    );
  } finally {
    setAlertsLoading(false);
  }
};
// Analyze uploaded PCAP file
const handlePcapAnalysis = async () => {
  if (!pcapFile) {
    setNetworkError("Please select a PCAP file first.");
    return;
  }

  setNetworkLoading(true);
  setNetworkError("");
  setNetworkAnalysis(null);

  try {
    const result = await analyzePcap(pcapFile);
    setNetworkAnalysis(result);
  } catch (error) {
    setNetworkError(
      error instanceof Error
        ? error.message
        : "PCAP analysis failed."
    );
  } finally {
    setNetworkLoading(false);
  }
};
async function loadNetworkAnomalies() {
  setAnomalyHistoryLoading(true);
  setAnomalyError("");

  try {
    const response = await getNetworkAnomalies(100, 0);
    setNetworkAnomalies(response.anomalies);
  } catch (error) {
    setAnomalyError(
      error instanceof Error ? error.message : "Unable to load anomaly history."
    );
  } finally {
    setAnomalyHistoryLoading(false);
  }
}
async function handleDetectAnomalies() {
  setAnomalyDetectionLoading(true);
  setAnomalyError("");
  setAnomalyDetectionResult(null);

  try {
    const response = await detectNetworkAnomalies();
    setAnomalyDetectionResult(response);
    await loadNetworkAnomalies();
  } catch (error) {
    setAnomalyError(
      error instanceof Error ? error.message : "Anomaly detection failed."
    );
  } finally {
    setAnomalyDetectionLoading(false);
  }
}
// Acknowledge an alert
const handleAcknowledgeAlert = async (alertId: number) => {
  setAlertsError("");

  try {
    await updateAlert(alertId, {
      status: "acknowledged",
    });

    await loadAlerts();
  } catch (error) {
    setAlertsError(
      error instanceof Error
        ? error.message
        : "Unable to acknowledge alert."
    );
  }
};

// Convert an alert into an incident
const handleConvertAlert = async (alertId: number) => {
  const confirmed = window.confirm(
    "Are you sure you want to convert this alert into an incident?"
  );

  if (!confirmed) return;

  setAlertsError("");

  try {
    await convertAlertToIncident(alertId);

    await Promise.all([
      loadAlerts(),
      loadIncidents(),
    ]);
  } catch (error) {
    setAlertsError(
      error instanceof Error
        ? error.message
        : "Unable to convert alert into incident."
    );
  }
};
async function loadAuditLogs() {
  setAuditLogsLoading(true);
  setAuditLogsError("");

  try {
    const params = new URLSearchParams({
      limit: "100",
    });

    if (auditLogActionFilter) {
      params.set("action", auditLogActionFilter);
    }

    const response = await apiFetch(
      `${API_BASE}/api/v1/audit-logs?${params.toString()}`
    );

    const data: unknown = await response.json();

    if (!response.ok) {
      throw new Error("Failed to load audit logs.");
    }

    const auditData = data as AuditLogsResponse;

    setAuditLogs(auditData.items);
  } catch (error) {
    setAuditLogsError(
      error instanceof Error
        ? error.message
        : "An unexpected error occurred while loading audit logs."
    );
  } finally {
    setAuditLogsLoading(false);
  }
}
async function generateComprehensiveReportCSV() {
  setReportGenerating(true);
  setReportError("");

  try {
    const pageSize = 100;

    // 1. Fetch all incidents
    const allIncidents: Incident[] = [];
    let incidentOffset = 0;
    let incidentTotal = Infinity;

    while (incidentOffset < incidentTotal) {
      const response = await apiFetch(
        `${API_BASE}/api/v1/incidents?skip=${incidentOffset}&limit=${pageSize}`
      );

      if (!response.ok) {
        throw new Error("Unable to fetch incident records.");
      }

      const data: {
        total: number;
        items: Incident[];
      } = await response.json();

      allIncidents.push(...data.items);
      incidentTotal = data.total;

      if (data.items.length === 0) break;
      incidentOffset += data.items.length;
    }

    // 2. Fetch all alerts
    const allAlerts: SecurityAlert[] = [];
    let alertOffset = 0;
    let alertTotal = Infinity;

    while (alertOffset < alertTotal) {
      const data = await getAlerts({
        skip: alertOffset,
        limit: pageSize,
      });

      allAlerts.push(...data.items);
      alertTotal = data.count;

      if (data.items.length === 0) break;
      alertOffset += data.items.length;
    }

    // 3. Fetch all network anomalies
    const allAnomalies: NetworkAnomaly[] = [];
    let anomalyOffset = 0;
    let anomalyTotal = Infinity;

    while (anomalyOffset < anomalyTotal) {
      const data = await getNetworkAnomalies(500, anomalyOffset);

      allAnomalies.push(...data.anomalies);
      anomalyTotal = data.total;

      if (data.anomalies.length === 0) break;
      anomalyOffset += data.anomalies.length;
    }

    // 4. Fetch audit logs (administrators only)
    const allAuditLogs: AuditLog[] = [];

    if (isAdmin) {
      let auditOffset = 0;
      let auditTotal = Infinity;

      while (auditOffset < auditTotal) {
        const response = await apiFetch(
          `${API_BASE}/api/v1/audit-logs?skip=${auditOffset}&limit=200`
        );

        if (!response.ok) {
          throw new Error("Unable to fetch audit logs.");
        }

        const data: {
          total: number;
          items: AuditLog[];
        } = await response.json();

        allAuditLogs.push(...data.items);
        auditTotal = data.total;

        if (data.items.length === 0) break;
        auditOffset += data.items.length;
      }
    }

    // 5. Prepare CSV rows
    const headers = [
      "Section",
      "Record ID",
      "Name / Description",
      "Severity / Action",
      "Status / Type",
      "Timestamp",
      "Source / Indicator",
      "Details",
    ];

    const rows: unknown[][] = [];

    const addSummary = (label: string, value: number | string) => {
      rows.push([
        "Summary",
        "",
        label,
        "",
        "",
        "",
        "",
        value,
      ]);
    };

    addSummary("Total Incidents", allIncidents.length);
    addSummary("Total Alerts", allAlerts.length);
    addSummary("Total Network Anomalies", allAnomalies.length);
    addSummary("Total Audit Logs", isAdmin ? allAuditLogs.length : "Not available for this role");
    // Incident severity breakdown
for (const severity of ["critical", "high", "medium", "low"]) {
  addSummary(
    `Incidents - ${severity}`,
    allIncidents.filter((item) => item.severity === severity).length
  );
}

// Incident status breakdown
for (const status of ["open", "investigating", "resolved", "closed"]) {
  addSummary(
    `Incidents - ${status}`,
    allIncidents.filter((item) => item.status === status).length
  );
}

// Alert severity breakdown
for (const severity of ["critical", "high", "medium", "low"]) {
  addSummary(
    `Alerts - ${severity}`,
    allAlerts.filter((item) => item.severity === severity).length
  );
}

// Alert status breakdown
for (const status of ["new", "open", "investigating", "resolved", "closed"]) {
  addSummary(
    `Alerts - ${status}`,
    allAlerts.filter((item) => item.status === status).length
  );
}

// Network anomaly status breakdown
const anomalyStatuses = [
  ...new Set(allAnomalies.map((item) => item.status)),
];

for (const status of anomalyStatuses) {
  addSummary(
    `Network Anomalies - ${status}`,
    allAnomalies.filter((item) => item.status === status).length
  );
}
    // Latest indicator analysis (not historical aggregate data)
if (result) {
  rows.push([
    "Latest Indicator Analysis",
    "",
    result.indicator,
    result.verdict,
    result.risk_level,
    new Date().toISOString(),
    result.indicator_type,
    JSON.stringify({
      format_valid: result.format_valid,
      evidence: result.evidence,
      details: result.details,
      recommendation: result.recommendation,
    }),
  ]);

  const threatIntel = result.threat_intelligence;

  if (threatIntel) {
    rows.push([
      "Latest Threat Intelligence",
      "",
      result.indicator,
      threatIntel.verdict ?? "Unknown",
      threatIntel.available ? "Available" : "Unavailable",
      new Date().toISOString(),
      threatIntel.source,
      JSON.stringify({
        risk_level: threatIntel.risk_level,
        reputation: threatIntel.reputation,
        analysis_stats: threatIntel.analysis_stats,
        error: threatIntel.error,
      }),
    ]);
  }
}

    // Incident records
    allIncidents.forEach((incident) => {
      rows.push([
        "Incident",
        incident.id,
        incident.title,
        incident.severity,
        incident.status,
        incident.created_at,
        incident.indicator ?? "",
        JSON.stringify({
          description: incident.description,
          assigned_to: incident.assigned_to,
          root_cause: incident.root_cause,
          resolution_summary: incident.resolution_summary,
        }),
      ]);
    });

    // Alert records
    allAlerts.forEach((alert) => {
      rows.push([
        "Alert",
        alert.id,
        alert.title,
        alert.severity,
        alert.status,
        alert.created_at,
        alert.indicator ?? "",
        JSON.stringify({
          source: alert.source,
          indicator_type: alert.indicator_type,
          risk_score: alert.risk_score,
          evidence: alert.evidence,
        }),
      ]);
    });

    // Network anomaly records
    allAnomalies.forEach((anomaly) => {
      rows.push([
        "Network Anomaly",
        anomaly.id,
        `${anomaly.source_ip} -> ${anomaly.destination_ip}`,
        "",
        anomaly.status,
        anomaly.detected_at,
        anomaly.protocol,
        JSON.stringify({
          anomaly_score: anomaly.anomaly_score,
          model_name: anomaly.model_name,
          flow_id: anomaly.flow_id,
        }),
      ]);
    });

    // Audit records
    allAuditLogs.forEach((log) => {
      rows.push([
        "Audit Log",
        log.id,
        log.username,
        log.action,
        log.resource_type ?? "",
        log.created_at ?? "",
        log.ip_address ?? "",
        JSON.stringify(log.details),
      ]);
    });

    // 6. Convert rows into CSV
    const escapeCSV = (value: unknown) => {
      const text = String(value ?? "");
      return `"${text.replace(/"/g, '""')}"`;
    };

    const csvContent = [
      headers.map(escapeCSV).join(","),
      ...rows.map((row) => row.map(escapeCSV).join(",")),
    ].join("\n");

    // 7. Download CSV
    const blob = new Blob([csvContent], {
      type: "text/csv;charset=utf-8;",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = `comprehensive-security-report-${new Date()
      .toISOString()
      .slice(0, 10)}.csv`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

  } catch (error) {
    setReportError(
      error instanceof Error
        ? error.message
        : "Unable to generate security report."
    );
  } finally {
    setReportGenerating(false);
  }
}
async function generateComprehensiveReportPDF() {
  setReportGenerating(true);
  setReportError("");

  try {
    const doc = new jsPDF();
    const pageSize = 100;

    // Fetch all incidents
    const allIncidents: Incident[] = [];
    let incidentOffset = 0;
    let incidentTotal = Infinity;

    while (incidentOffset < incidentTotal) {
      const response = await apiFetch(
        `${API_BASE}/api/v1/incidents?skip=${incidentOffset}&limit=${pageSize}`
      );

      if (!response.ok) {
        throw new Error("Unable to fetch incidents.");
      }

      const data: { total: number; items: Incident[] } =
        await response.json();

      allIncidents.push(...data.items);
      incidentTotal = data.total;

      if (!data.items.length) break;
      incidentOffset += data.items.length;
    }

    // Fetch all alerts
    const allAlerts: SecurityAlert[] = [];
    let alertOffset = 0;
    let alertTotal = Infinity;

    while (alertOffset < alertTotal) {
      const data = await getAlerts({
        skip: alertOffset,
        limit: pageSize,
      });

      allAlerts.push(...data.items);
      alertTotal = data.count;

      if (!data.items.length) break;
      alertOffset += data.items.length;
    }

    // Fetch all network anomalies
    const allAnomalies: NetworkAnomaly[] = [];
    let anomalyOffset = 0;
    let anomalyTotal = Infinity;

    while (anomalyOffset < anomalyTotal) {
      const data = await getNetworkAnomalies(500, anomalyOffset);

      allAnomalies.push(...data.anomalies);
      anomalyTotal = data.total;

      if (!data.anomalies.length) break;
      anomalyOffset += data.anomalies.length;
    }

    // Fetch audit logs for administrators
    const allAuditLogs: AuditLog[] = [];

    if (isAdmin) {
      let auditOffset = 0;
      let auditTotal = Infinity;

      while (auditOffset < auditTotal) {
        const response = await apiFetch(
          `${API_BASE}/api/v1/audit-logs?skip=${auditOffset}&limit=200`
        );

        if (!response.ok) {
          throw new Error("Unable to fetch audit logs.");
        }

        const data: { total: number; items: AuditLog[] } =
          await response.json();

        allAuditLogs.push(...data.items);
        auditTotal = data.total;

        if (!data.items.length) break;
        auditOffset += data.items.length;
      }
    }

    // PDF title and metadata
    const date = new Date().toLocaleString();

    doc.setFontSize(20);
    doc.setFont("helvetica", "bold");
    doc.text("CYBER DEFENCE PLATFORM", 14, 20);

    doc.setFontSize(15);
    doc.text("Comprehensive Security Report", 14, 31);

    doc.setFontSize(9);
    doc.setFont("helvetica", "normal");
    doc.text(`Generated: ${date}`, 14, 40);
    doc.text("Classification: Internal Security Report", 14, 46);

    // Executive summary
    autoTable(doc, {
      startY: 55,
      head: [["Security Metric", "Total"]],
      body: [
        ["Incidents", String(allIncidents.length)],
        ["Alerts", String(allAlerts.length)],
        ["Network Anomalies", String(allAnomalies.length)],
        ["Audit Logs", isAdmin ? String(allAuditLogs.length) : "Restricted"],
      ],
      theme: "grid",
      headStyles: { fillColor: [25, 45, 75] },
    });

    // Incident severity summary
    const incidentSeverities = ["critical", "high", "medium", "low"];

    autoTable(doc, {
      startY: (doc as any).lastAutoTable.finalY + 12,
      head: [["Incident Severity", "Count"]],
      body: incidentSeverities.map((severity) => [
        severity.toUpperCase(),
        String(
          allIncidents.filter((item) => item.severity === severity).length
        ),
      ]),
      theme: "grid",
      headStyles: { fillColor: [25, 45, 75] },
    });

    // Incident status summary
    const incidentStatuses = [
      "open",
      "investigating",
      "resolved",
      "closed",
    ];

    autoTable(doc, {
      startY: (doc as any).lastAutoTable.finalY + 12,
      head: [["Incident Status", "Count"]],
      body: incidentStatuses.map((status) => [
        status.toUpperCase(),
        String(
          allIncidents.filter((item) => item.status === status).length
        ),
      ]),
      theme: "grid",
      headStyles: { fillColor: [25, 45, 75] },
    });

    // Alert summary
    autoTable(doc, {
      startY: (doc as any).lastAutoTable.finalY + 12,
      head: [["Alert Severity", "Count"]],
      body: incidentSeverities.map((severity) => [
        severity.toUpperCase(),
        String(
          allAlerts.filter((item) => item.severity === severity).length
        ),
      ]),
      theme: "grid",
      headStyles: { fillColor: [25, 45, 75] },
    });

    // Network anomaly summary
    const anomalyStatuses = [
      ...new Set(allAnomalies.map((item) => item.status)),
    ];

    autoTable(doc, {
      startY: (doc as any).lastAutoTable.finalY + 12,
      head: [["Network Anomaly Status", "Count"]],
      body: anomalyStatuses.map((status) => [
        status,
        String(
          allAnomalies.filter((item) => item.status === status).length
        ),
      ]),
      theme: "grid",
      headStyles: { fillColor: [25, 45, 75] },
    });

    // Latest indicator analysis
    if (result) {
      doc.addPage();

      doc.setFontSize(15);
      doc.setFont("helvetica", "bold");
      doc.text("Latest Indicator Analysis", 14, 20);

      autoTable(doc, {
        startY: 28,
        head: [["Field", "Value"]],
        body: [
          ["Indicator", result.indicator],
          ["Indicator Type", result.indicator_type],
          ["Verdict", result.verdict],
          ["Risk Level", result.risk_level],
          ["Format Valid", String(result.format_valid)],
          ["Recommendation", result.recommendation ?? "Not available"],
        ],
        theme: "grid",
        styles: { overflow: "linebreak" },
      });

      if (result.threat_intelligence) {
        const ti = result.threat_intelligence;

        autoTable(doc, {
          startY: (doc as any).lastAutoTable.finalY + 12,
          head: [["Threat Intelligence", "Value"]],
          body: [
            ["Source", ti.source],
            ["Available", String(ti.available)],
            ["Verdict", ti.verdict ?? "Unknown"],
            ["Risk Level", ti.risk_level ?? "Unknown"],
            ["Reputation", String(ti.reputation ?? "Not available")],
            ["Malicious", String(ti.analysis_stats?.malicious ?? 0)],
            ["Suspicious", String(ti.analysis_stats?.suspicious ?? 0)],
            ["Harmless", String(ti.analysis_stats?.harmless ?? 0)],
            ["Undetected", String(ti.analysis_stats?.undetected ?? 0)],
          ],
          theme: "grid",
        });
      }
    }

    // Detailed incident records
    doc.addPage();
    doc.setFontSize(15);
    doc.setFont("helvetica", "bold");
    doc.text("Incident Records", 14, 20);

    autoTable(doc, {
      startY: 27,
      head: [["ID", "Title", "Severity", "Status", "Created"]],
      body: allIncidents.map((item) => [
        String(item.id),
        item.title,
        item.severity,
        item.status,
        item.created_at,
      ]),
      theme: "grid",
      styles: { fontSize: 7, overflow: "linebreak" },
      headStyles: { fillColor: [25, 45, 75] },
    });

    // Detailed alert records
    doc.addPage();
    doc.setFontSize(15);
    doc.text("Security Alert Records", 14, 20);

    autoTable(doc, {
      startY: 27,
      head: [["ID", "Title", "Severity", "Status", "Risk Score"]],
      body: allAlerts.map((item) => [
        String(item.id),
        item.title,
        item.severity,
        item.status,
        String(item.risk_score ?? "N/A"),
      ]),
      theme: "grid",
      styles: { fontSize: 7, overflow: "linebreak" },
      headStyles: { fillColor: [25, 45, 75] },
    });

    // Detailed anomaly records
    doc.addPage();
    doc.setFontSize(15);
    doc.text("Network Anomaly Records", 14, 20);

    autoTable(doc, {
      startY: 27,
      head: [
        ["ID", "Source IP", "Destination IP", "Protocol", "Score", "Status"],
      ],
      body: allAnomalies.map((item) => [
        String(item.id),
        item.source_ip,
        item.destination_ip,
        item.protocol,
        String(item.anomaly_score),
        item.status,
      ]),
      theme: "grid",
      styles: { fontSize: 7, overflow: "linebreak" },
      headStyles: { fillColor: [25, 45, 75] },
    });

    // Audit logs (administrators only)
    if (isAdmin) {
      doc.addPage();
      doc.setFontSize(15);
      doc.text("Security Audit Records", 14, 20);

      autoTable(doc, {
        startY: 27,
        head: [["ID", "User", "Action", "Resource", "Timestamp"]],
        body: allAuditLogs.map((item) => [
          String(item.id),
          item.username,
          item.action,
          item.resource_type ?? "",
          item.created_at ?? "",
        ]),
        theme: "grid",
        styles: { fontSize: 7, overflow: "linebreak" },
        headStyles: { fillColor: [25, 45, 75] },
      });
    }

    // Add page numbers
    const pageCount = doc.getNumberOfPages();

    for (let page = 1; page <= pageCount; page++) {
      doc.setPage(page);
      doc.setFontSize(8);
      doc.setFont("helvetica", "normal");
      doc.text(
        `Cyber Defence Platform | Page ${page} of ${pageCount}`,
        14,
        290
      );
    }

    // Download PDF
    doc.save(
      `comprehensive-security-report-${new Date()
        .toISOString()
        .slice(0, 10)}.pdf`
    );

  } catch (error) {
    setReportError(
      error instanceof Error
        ? error.message
        : "Unable to generate PDF report."
    );
  } finally {
    setReportGenerating(false);
  }
}
function exportAuditLogsCSV() {
  if (auditLogs.length === 0) {
    alert("No audit logs available to export.");
    return;
  }

  const headers = [
    "ID",
    "Timestamp",
    "Username",
    "Action",
    "Resource Type",
    "Resource ID",
    "IP Address",
    "Details",
  ];

  const escapeCSV = (value: unknown) => {
    const text = String(value ?? "");
    return `"${text.replace(/"/g, '""')}"`;
  };

  const rows = auditLogs.map((log) => [
    log.id,
    log.created_at,
    log.username,
    log.action,
    log.resource_type,
    log.resource_id,
    log.ip_address,
    JSON.stringify(log.details),
  ]);

  const csvContent = [
    headers.map(escapeCSV).join(","),
    ...rows.map((row) => row.map(escapeCSV).join(",")),
  ].join("\n");

  const blob = new Blob([csvContent], {
    type: "text/csv;charset=utf-8;",
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = `audit-logs-${new Date().toISOString().slice(0, 10)}.csv`;

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  URL.revokeObjectURL(url);
}
async function openIncident(incident: Incident) {
  setSelectedIncident(incident);
  setAssignedTo(incident.assigned_to ?? "");
setRootCause(incident.root_cause ?? "");
setResolutionSummary(incident.resolution_summary ?? "");
  setInvestigationLoading(true);
  setInvestigationError("");

  try {
    const [activityResponse, notesResponse] = await Promise.all([
      apiFetch(
        `${API_BASE}/api/v1/incidents/${incident.id}/activities`
      ),
      apiFetch(
        `${API_BASE}/api/v1/incidents/${incident.id}/notes`
      ),
    ]);

    if (!activityResponse.ok || !notesResponse.ok) {
      throw new Error("Unable to load investigation details.");
    }

    const activityData: InvestigationResponse<IncidentActivity> =
      await activityResponse.json();

    const notesData: InvestigationResponse<IncidentNote> =
      await notesResponse.json();

    setIncidentActivities(activityData.items);
    setIncidentNotes(notesData.items);
  } catch (err) {
    setInvestigationError(
      err instanceof Error
        ? err.message
        : "Unable to load investigation."
    );
  } finally {
    setInvestigationLoading(false);
  }
}

async function submitInvestigationNote() {
  if (!selectedIncident || !newNote.trim()) return;

  setNoteSaving(true);
  setInvestigationError("");

  try {
    const response = await apiFetch(
      `${API_BASE}/api/v1/incidents/${selectedIncident.id}/notes`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          note: newNote.trim(),
          author: "Security Analyst",
        }),
      }
    );

    if (!response.ok) {
      throw new Error("Unable to save analyst note.");
    }

    setNewNote("");
    await openIncident(selectedIncident);
  } catch (err) {
    setInvestigationError(
      err instanceof Error
        ? err.message
        : "Unable to save note."
    );
  } finally {
    setNoteSaving(false);
  }
}

async function createIncident(event: FormEvent<HTMLFormElement>) {
  event.preventDefault();
  setIncidentFormError("");

  if (incidentTitle.trim().length < 3) {
    setIncidentFormError("Title must contain at least 3 characters.");
    return;
  }

  setIncidentSaving(true);

  try {
    const response = await apiFetch(`${API_BASE}/api/v1/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: incidentTitle.trim(),
        description: incidentDescription.trim(),
        severity: incidentSeverity,
        status: "open",
        indicator_type: incidentIndicator.trim()
          ? incidentIndicatorType
          : null,
        indicator: incidentIndicator.trim() || null,
      }),
    });

    const data: unknown = await response.json();

    if (!response.ok) {
      throw new Error(
        `Could not create incident: ${formatValue(
          typeof data === "object" &&
            data !== null &&
            "detail" in data
            ? data.detail
            : data
        )}`
      );
    }

    setIncidentTitle("");
    setIncidentDescription("");
    setIncidentIndicator("");
    setIncidentSeverity("medium");
    setIncidentFormError("");

    await loadIncidents();
  } catch (err) {
    setIncidentFormError(
      err instanceof Error
        ? err.message
        : "Unable to create incident."
    );
  } finally {
    setIncidentSaving(false);
  }
}

async function updateIncidentStatus(
  incidentId: number,
  status: IncidentStatus
) {
  setIncidentsError("");

  try {
    const response = await apiFetch(
      `${API_BASE}/api/v1/incidents/${incidentId}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      }

    );


    if (!response.ok) {
      const data: unknown = await response.json();

      throw new Error(
        `Update failed: ${formatValue(
          typeof data === "object" &&
            data !== null &&
            "detail" in data
            ? data.detail
            : data
        )}`
      );
    }

    await loadIncidents();
  } catch (err) {
    setIncidentsError(
      err instanceof Error
        ? err.message
        : "Unable to update incident."
    );
  }

}

async function saveIncidentManagementDetails() {
  if (!selectedIncident) return;

  setIncidentUpdateSaving(true);
  setInvestigationError("");

  try {
    const response = await apiFetch(
      `${API_BASE}/api/v1/incidents/${selectedIncident.id}`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          assigned_to: assignedTo.trim(),
          root_cause: rootCause.trim(),
          resolution_summary: resolutionSummary.trim(),
        }),
      }
    );

    if (!response.ok) {
      const data = await response.json();

      throw new Error(
        `Incident update failed: ${formatValue(
          data.detail ?? data
        )}`
      );
    }

    const updatedIncident: Incident = await response.json();

    // Update the selected incident
    setSelectedIncident(updatedIncident);

    // Update the incident register
    setIncidents((previous) =>
      previous.map((incident) =>
        incident.id === updatedIncident.id
          ? updatedIncident
          : incident
      )
    );

    // Refresh investigation timeline and notes
    await openIncident(updatedIncident);

  } catch (err) {
    setInvestigationError(
      err instanceof Error
        ? err.message
        : "Unable to update incident details."
    );
  } finally {
    setIncidentUpdateSaving(false);
  }
}

function prepareIncidentFromAnalysis() {
  if (!result) return;

  const risk = result.risk_level?.toLowerCase();

  const suggestedSeverity: IncidentSeverity =
    risk === "critical"
      ? "critical"
      : risk === "high"
        ? "high"
        : risk === "low"
          ? "low"
          : "medium";

  setIncidentTitle(`Investigation: ${result.indicator}`.slice(0, 200));

  setIncidentDescription(
    [
      "Incident created from indicator analysis.",
      `Indicator type: ${result.indicator_type}`,
      `Format valid: ${result.format_valid ? "Yes" : "No"}`,
      `Verdict: ${result.verdict || "Unknown"}`,
      `Risk level: ${result.risk_level || "Unknown"}`,
      result.recommendation
        ? `Recommendation: ${result.recommendation}`
        : "",
    ]
      .filter(Boolean)
      .join("\n")
      .slice(0, 2000)
  );

  setIncidentSeverity(suggestedSeverity);
  setIncidentIndicatorType(result.indicator_type as IndicatorType);
  setIncidentIndicator(result.indicator);
  setIncidentFormError("");
}
useEffect(() => {
  if (!currentUser) return;

  loadHistory();
}, [currentUser]);
useEffect(() => {
  if (!currentUser) return;

  loadIncidents();
}, [incidentStatusFilter, incidentSeverityFilter, currentUser]);
// Load alerts when the Alerts page is opened or filters change
useEffect(() => {
  if (!currentUser || activePage !== "alerts") return;

  void loadAlerts();
}, [
  currentUser,
  activePage,
  alertSearch,
  alertSeverityFilter,
  alertStatusFilter,
]);
// Load audit logs when the Audit Logs page is opened
useEffect(() => {
  if (!currentUser || !isAdmin || activePage !== "audit-logs") return;

  void loadAuditLogs();
}, [currentUser, isAdmin, activePage, auditLogActionFilter]);
// Load security data when the Overview page is opened
useEffect(() => {
  if (!currentUser || activePage !== "overview") return;

  void loadAlerts();
  void loadNetworkAnomalies();
}, [currentUser, activePage]);
// Load network anomalies when the Anomaly Detection page is opened
useEffect(() => {
  if (!currentUser || activePage !== "anomalies") return;
  void loadNetworkAnomalies();
}, [currentUser, activePage]);
  async function analyzeIndicator(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const value = indicator.trim();
    if (!value) {
      setAnalysisError("Enter an indicator to analyze.");
      return;
    }

    setLoading(true);
    setAnalysisError("");
    setResult(null);

    try {
      const response = await apiFetch(
        `${API_BASE}/api/v1/indicators/analyze`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            indicator_type: indicatorType,
            value: value,
          }),
        }
      );

      const data: unknown = await response.json();

      if (!response.ok) {
        const message =
          typeof data === "object" &&
          data !== null &&
          "detail" in data
            ? formatValue(data.detail)
            : `Request failed with status ${response.status}`;

        throw new Error(message);
      }

      setResult(data as AnalysisResult);
      void loadHistory();
    } catch (err) {
      setAnalysisError(
        err instanceof Error
          ? err.message
          : "Could not complete the analysis request."
      );
    } finally {
      setLoading(false);
    }
  }
  if (authChecking) {
    return (
      <main className="shell">
        <section className="content">
          <h2>Checking authentication...</h2>
          <p>Please wait while your session is verified.</p>
        </section>
      </main>
    );
  }


  if (!currentUser) {
    return (
      <main
        style={{
          minHeight: "100vh",
          width: "100%",
          display: "grid",
          placeItems: "center",
          padding: 24,
          boxSizing: "border-box",
          background: "#080e19",
        }}
      >
        <section
          style={{
            width: "100%",
            maxWidth: 420,
            padding: 32,
            boxSizing: "border-box",
            border: "1px solid #263449",
            borderRadius: 18,
            background: "#0f1929",
            boxShadow: "0 20px 60px rgba(0,0,0,0.35)",
          }}
        >
          <ShieldCheck size={42} color="#60a5fa" />

          <h1 style={{ marginTop: 20, fontSize: 28 }}>
            CYBERGUARD
          </h1>

          <p style={{ color: "#94a3b8", marginBottom: 28 }}>
            Sign in to your security operations platform.
          </p>

          <form
            onSubmit={handleLogin}
            style={{ display: "grid", gap: 18 }}
          >
            <div>
              <label htmlFor="loginIdentifier">
                Username or Email
              </label>
              <input
                id="loginIdentifier"
                value={loginIdentifier}
                onChange={(e) => setLoginIdentifier(e.target.value)}
                required
                autoComplete="username"
                style={{ ...fieldStyle, marginTop: 8 }}
              />
            </div>

            <div>
              <label htmlFor="loginPassword">
                Password
              </label>
              <input
                id="loginPassword"
                type="password"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                required
                autoComplete="current-password"
                style={{ ...fieldStyle, marginTop: 8 }}
              />
            </div>

            {loginError && (
              <p role="alert" style={{ color: "#fca5a5" }}>
                {loginError}
              </p>
            )}

            <button
              type="submit"
              disabled={loginLoading}
              style={{
                padding: 13,
                border: 0,
                borderRadius: 8,
                background: "#2563eb",
                color: "white",
                fontWeight: 600,
                fontSize: 15,
                cursor: loginLoading ? "wait" : "pointer",
              }}
            >
              {loginLoading ? "Signing in..." : "Sign in"}
            </button>
          </form>

          <p
            style={{
              marginTop: 24,
              fontSize: 12,
              color: "#64748b",
              textAlign: "center",
            }}
          >
            CYBERGUARD SECURITY OPERATIONS
          </p>
        </section>
      </main>
    );
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="mark">
          <ShieldCheck size={24} />
        </div>
        <h2>
          CYBER<span>GUARD</span>
        </h2>
        <small>DEFENCE PLATFORM</small>

        <p className="label">WORKSPACE</p>
      <div
  className={`nav ${activePage === "overview" ? "active" : ""}`}
  onClick={() => setActivePage("overview")}
  style={{ cursor: "pointer" }}
>
  <Activity size={17} /> Overview
</div>
        <div className="nav">
          <Database size={17} /> Threat analysis
        </div>
        <div
  className="nav"
  onClick={() => {
    document
      .getElementById("incident-management")
      ?.scrollIntoView({ behavior: "smooth", block: "start" });

    void loadIncidents();
  }}
  style={{ cursor: "pointer" }}
>
  <Server size={17} /> Incidents
</div>
{isAdmin && (
  <div
    className={`nav ${activePage === "users" ? "active" : ""}`}
    onClick={() => {
      setActivePage("users");
      void loadAdminUsers();
    }}
    style={{ cursor: "pointer" }}
  >
    <ShieldCheck size={17} /> User Management
  </div>
)}
<div
  className={`nav ${activePage === "alerts" ? "active" : ""}`}
  onClick={() => {
    setActivePage("alerts");
    void loadAlerts();
  }}
  style={{ cursor: "pointer" }}
>
  <ShieldCheck size={17} /> Security Alerts
</div>
<div
  className={`nav ${activePage === "network" ? "active" : ""}`}
  onClick={() => setActivePage("network")}
  style={{ cursor: "pointer" }}
>
  <Activity size={17} /> Network Traffic
</div>
<div
  className={`nav ${activePage === "anomalies" ? "active" : ""}`}
  onClick={() => setActivePage("anomalies")}
  style={{ cursor: "pointer" }}
>
  <ShieldCheck size={17} /> Anomaly Detection
</div>
<div
  className={`nav ${activePage === "ai-analysis" ? "active" : ""}`}
  onClick={() => setActivePage("ai-analysis")}
  style={{ cursor: "pointer" }}
>
  <BrainCircuit size={17} /> AI Security Analysis
</div>
{isAdmin && (
  <div
    className={`nav ${activePage === "audit-logs" ? "active" : ""}`}
    onClick={() => setActivePage("audit-logs")}
    style={{ cursor: "pointer" }}
  >
    <ClipboardList size={17} /> Audit Logs
  </div>
)}
<footer
  style={{
    marginTop: "auto",
    padding: 16,
    borderTop: "1px solid #263449",
    display: "grid",
    gap: 12,
  }}
>
  <div>
    <strong>{currentUser.username}</strong>
    <p
      style={{
        margin: "5px 0 0",
        color: "#94a3b8",
        fontSize: 12,
        textTransform: "uppercase",
      }}
    >
      {currentUser.role}
    </p>
  </div>

  <button
    type="button"
    onClick={handleLogout}
    style={{
      padding: 10,
      border: "1px solid #334155",
      borderRadius: 8,
      background: "#1e293b",
      color: "#e2e8f0",
      cursor: "pointer",
      fontWeight: 600,
    }}
  >
    Sign out
  </button>
</footer>

      </aside>

      <section className="content">
        {activePage === "overview" && (
  <>
        <header>
  <div>
    <small>SECURITY OPERATIONS / OVERVIEW</small>
    <h1>Defence overview</h1>
  </div>

  <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
    <button
      type="button"
      onClick={() => void generateComprehensiveReportCSV()}
      disabled={reportGenerating}
    >
      {reportGenerating ? "Generating report..." : "Generate Security Report"}
    </button>
<button
  type="button"
  onClick={() => void generateComprehensiveReportPDF()}
  disabled={reportGenerating}
>
  {reportGenerating ? "Generating PDF..." : "Export PDF"}
</button>
    <span className="pill">
      <b /> DEVELOPMENT
    </span>
  </div>
</header>

{reportError && (
  <p style={{ color: "#dc2626", marginTop: 12 }}>
    {reportError}
  </p>
)}

        <section className="hero">
          <small>PLATFORM STATUS</small>
          <h2>Build a clearer security picture.</h2>
          <p>
            A defensive workspace for indicator analysis,
            anomaly detection, and incident investigation.
          </p>
          <ShieldCheck className="hero-icon" size={56} />
        </section>

        <div className="cards">
          <article>
            <Activity />
            <small>API STATUS</small>
            <strong>
              {health?.status === "ok"
                ? "Operational"
                : "Checking..."}
            </strong>
       <p>{health?.service ?? (error || "Waiting for API response")}</p>
          </article>

          <article>
            <Database />
            <small>DATABASE</small>
            <strong>Not connected</strong>
            <p>Connection milestone pending</p>
          </article>

          <article>
            <ShieldCheck />
            <small>ANALYSIS ENGINE</small>
            <strong>
              {result ? "Responding" : "Validation ready"}
            </strong>
            <p>
              {result
                ? "Indicator analysis response received"
                : "Threat intelligence not yet configured"}
            </p>
          </article>
        </div>
        {/* Security KPI cards */}
        <section
          className="panel"
          style={{ marginTop: 24 }}
        >
          <small>SECURITY METRICS</small>
          <h3>Security at a glance</h3>

          <div className="cards" style={{ marginTop: 16 }}>
            <article>
              <AlertCircle />
              <small>INCIDENTS LOADED</small>
              <strong>{incidents.length}</strong>
              <p>Incidents returned by the API</p>
            </article>

            <article>
              <Activity />
              <small>OPEN INCIDENTS</small>
              <strong>
                {incidents.filter(
                  (incident) =>
                    incident.status === "open" ||
                    incident.status === "investigating"
                ).length}
              </strong>
              <p>Open or under investigation</p>
            </article>

            <article>
              <ShieldCheck />
              <small>ALERTS LOADED</small>
              <strong>{alerts.length}</strong>
              <p>Alerts returned by the API</p>
            </article>

            <article>
              <Activity />
              <small>ANOMALIES LOADED</small>
              <strong>{networkAnomalies.length}</strong>
              <p>Network anomalies returned by the API</p>
            </article>
          </div>
        </section>

        {/* Security severity breakdown */}
        <section
          className="panel"
          style={{ marginTop: 24 }}
        >
          <small>THREAT DISTRIBUTION</small>
          <h3>Severity breakdown</h3>

          <h4 style={{ marginTop: 20 }}>Incidents by severity</h4>
          <div className="cards" style={{ marginTop: 12 }}>
            <article>
              <small>CRITICAL</small>
              <strong>{incidentSeverityCounts.critical}</strong>
            </article>
            <article>
              <small>HIGH</small>
              <strong>{incidentSeverityCounts.high}</strong>
            </article>
            <article>
              <small>MEDIUM</small>
              <strong>{incidentSeverityCounts.medium}</strong>
            </article>
            <article>
              <small>LOW</small>
              <strong>{incidentSeverityCounts.low}</strong>
            </article>
          </div>

          <h4 style={{ marginTop: 24 }}>Alerts by severity</h4>
          <div className="cards" style={{ marginTop: 12 }}>
            <article>
              <small>CRITICAL</small>
              <strong>{alertSeverityCounts.critical}</strong>
            </article>
            <article>
              <small>HIGH</small>
              <strong>{alertSeverityCounts.high}</strong>
            </article>
            <article>
              <small>MEDIUM</small>
              <strong>{alertSeverityCounts.medium}</strong>
            </article>
            <article>
              <small>LOW</small>
              <strong>{alertSeverityCounts.low}</strong>
            </article>
          </div>
        </section>

        {/* Alert severity chart */}
        <section className="panel" style={{ marginTop: 24 }}>
          <small>SECURITY ANALYTICS</small>
          <h3>Alert Severity Distribution</h3>

          <div style={{ width: "100%", height: 300, marginTop: 20 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={alertSeverityChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="severity" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" name="Alerts" fill="#f59e0b" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        {/* Incident severity chart */}
        <section className="panel" style={{ marginTop: 24 }}>
          <small>SECURITY ANALYTICS</small>
          <h3>Incident Severity Distribution</h3>

          <div style={{ width: "100%", height: 300, marginTop: 20 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={incidentSeverityChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="severity" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" name="Incidents" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        {/* Incident status breakdown */}
        <section
          className="panel"
          style={{ marginTop: 24 }}
        >
          <small>INCIDENT MANAGEMENT</small>
          <h3>Incidents by status</h3>

          <div className="cards" style={{ marginTop: 12 }}>
            <article>
              <small>OPEN</small>
              <strong>{incidentStatusCounts.open}</strong>
            </article>
            <article>
              <small>INVESTIGATING</small>
              <strong>{incidentStatusCounts.investigating}</strong>
            </article>
            <article>
              <small>RESOLVED</small>
              <strong>{incidentStatusCounts.resolved}</strong>
            </article>
            <article>
              <small>CLOSED</small>
              <strong>{incidentStatusCounts.closed}</strong>
            </article>
          </div>
        </section>

        {/* Incident status chart */}
        <section className="panel" style={{ marginTop: 24 }}>
          <small>SECURITY ANALYTICS</small>
          <h3>Incident Status Distribution</h3>

          <div style={{ width: "100%", height: 300, marginTop: 20 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={incidentStatusChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="status" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" name="Incidents" fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
{/* Latest Indicator Threat Intelligence */}
{result?.threat_intelligence?.available && (
  <section className="panel" style={{ marginTop: 24 }}>
    <h2>Latest Indicator Threat Intelligence</h2>
    <p>
      Detection statistics from the most recently analyzed indicator.
    </p>

    {threatIntelligenceChartData.some((item) => item.value > 0) ? (
      <div style={{ width: "100%", height: 320 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={threatIntelligenceChartData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={100}
              label
            >
              {threatIntelligenceChartData.map((entry, index) => (
                <Cell
                  key={entry.name}
                  fill={
                    ["#ef4444", "#f59e0b", "#22c55e", "#64748b"][index]
                  }
                />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>
    ) : (
      <p>No detection statistics were returned for the latest indicator.</p>
    )}
  </section>
)}
        {/* Indicator analysis */}
        {canAnalyze && (
       <section
    className="panel"
    style={{ marginTop: 24 }}
  >
          <small>SECURITY TOOL</small>
          <h3>Indicator analysis</h3>
          <p>
            Submit an indicator for format validation and
            preliminary analysis.
          </p>

          <form
            onSubmit={analyzeIndicator}
            style={{
              display: "grid",
              gap: 14,
              marginTop: 20,
            }}
          >
            <div>
              <label
                htmlFor="indicatorType"
                style={{ display: "block", marginBottom: 8 }}
              >
                Indicator type
              </label>
              <select
                id="indicatorType"
                value={indicatorType}
                onChange={(event) => {
                  setIndicatorType(event.target.value as IndicatorType);
                  setResult(null);
                  setAnalysisError("");
                }}
                style={fieldStyle}
              >
                <option value="ip">IP address</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">File hash (MD5 / SHA-1 / SHA-256)</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="indicator"
                style={{ display: "block", marginBottom: 8 }}
              >
                Indicator value
              </label>
              <input
                id="indicator"
                value={indicator}
                onChange={(event) => setIndicator(event.target.value)}
                placeholder={
                  indicatorType === "ip"
                    ? "Example: 8.8.8.8"
                    : indicatorType === "domain"
                      ? "Example: example.com"
                      : indicatorType === "url"
                        ? "Example: https://example.com/path"
                        : "Paste a file hash"
                }
                autoComplete="off"
                spellCheck={false}
                style={fieldStyle}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              style={{
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                gap: 8,
                padding: "12px 16px",
                border: 0,
                borderRadius: 8,
                background: loading ? "#475569" : "#2563eb",
                color: "white",
                cursor: loading ? "wait" : "pointer",
                fontWeight: 600,
              }}
            >
              {loading ? (
                <LoaderCircle size={18} />
              ) : (
                <Search size={18} />
              )}
              {loading ? "Analyzing..." : "Analyze indicator"}
            </button>
          </form>

          {analysisError && (
            <div
              role="alert"
              style={{
                marginTop: 18,
                padding: 14,
                borderRadius: 8,
                border: "1px solid #7f1d1d",
                color: "#fecaca",
                background: "#450a0a",
              }}
            >
              <AlertCircle
                size={17}
                style={{
                  verticalAlign: "middle",
                  marginRight: 8,
                }}
              />
              {analysisError}
            </div>
          )}

          {result && (
            <section
              aria-live="polite"
              style={{
                marginTop: 24,
                padding: 18,
                borderRadius: 10,
                border: "1px solid #334155",
                background: "#0b1220",
                display: "grid",
                gap: 14,
              }}
            >
              <div>
                <small>ANALYSIS RESULT</small>
                <h3 style={{ overflowWrap: "anywhere" }}>
                  {result.indicator}
                </h3>
                <p>Type: {result.indicator_type}</p>
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns:
                    "repeat(auto-fit, minmax(140px, 1fr))",
                  gap: 12,
                }}
              >
                <div>
                  <small>FORMAT VALID</small>
                  <p style={{ fontWeight: 700 }}>
                    {result.format_valid ? "Yes" : "No"}
                  </p>
                </div>
                <div>
                  <small>VERDICT</small>
                  <p style={{ fontWeight: 700 }}>
                    {result.verdict || "Unknown"}
                  </p>
                </div>
                <div>
                  <small>RISK LEVEL</small>
                  <p style={{ fontWeight: 700 }}>
                    {result.risk_level || "Unknown"}
                  </p>
                </div>
              </div>

              <div>
                <strong>Evidence</strong>
                <pre
                  style={{
                    ...fieldStyle,
                    whiteSpace: "pre-wrap",
                    overflowWrap: "anywhere",
                    fontFamily: "inherit",
                  }}
                >
                  {formatValue(result.evidence)}
                </pre>
              </div>

              {result.details !== undefined && (
                <div>
                  <strong>Details</strong>
                  <pre
                    style={{
                      ...fieldStyle,
                      whiteSpace: "pre-wrap",
                      overflowWrap: "anywhere",
                      fontFamily: "inherit",
                    }}
                  >
                    {formatValue(result.details)}
                  </pre>
                </div>
              )}

              {result.recommendation && (
                <div>
                  <strong>Recommendation</strong>
                  <p>{result.recommendation}</p>
                </div>
              )}

 <div style={{ marginTop: 12 }}>
  <button
    type="button"
    onClick={prepareIncidentFromAnalysis}
    style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 8,
      padding: "12px 16px",
      border: "1px solid #2c6857",
      borderRadius: 8,
      background: "#12332d",
      color: "#a7f3d0",
      cursor: "pointer",
      fontWeight: 600,
    }}
  >
    <ShieldCheck size={18} />
    Create incident from this analysis
  </button>

  <p style={{ fontSize: 12, color: "#94a3b8" }}>
    Prefills an incident draft using this analysis result.
    Review the details before submitting.
  </p>
</div>

{result.threat_intelligence && (
  <div className="threat-intelligence">
    <h3>Threat Intelligence</h3>

    <p>
      <strong>Source:</strong>{" "}
      {result.threat_intelligence.source}
    </p>

    {result.threat_intelligence.available ? (
      <>
        <p>
          <strong>Verdict:</strong>{" "}
          {result.threat_intelligence.verdict ?? "Unknown"}
        </p>

        <p>
          <strong>Risk Level:</strong>{" "}
          {result.threat_intelligence.risk_level ?? "Unknown"}
        </p>

        <p>
          <strong>Reputation:</strong>{" "}
          {result.threat_intelligence.reputation ?? "Not available"}
        </p>

        <h4>Detection Statistics</h4>

        <div className="detection-stats">
          <p>
            Malicious:{" "}
            {result.threat_intelligence.analysis_stats?.malicious ?? 0}
          </p>
          <p>
            Suspicious:{" "}
            {result.threat_intelligence.analysis_stats?.suspicious ?? 0}
          </p>
          <p>
            Harmless:{" "}
            {result.threat_intelligence.analysis_stats?.harmless ?? 0}
          </p>
          <p>
            Undetected:{" "}
            {result.threat_intelligence.analysis_stats?.undetected ?? 0}
          </p>
        </div>
      </>
    ) : (
      <p>
        Intelligence lookup unavailable:{" "}
        {result.threat_intelligence.error ?? "No additional details"}
      </p>
    )}
  </div>
)}


              <p style={{ fontSize: 12, opacity: 0.75 }}>
                A valid format does not establish that an indicator
                is safe. Threat-intelligence verification is not yet
                implied by this result.
              </p>
            </section>
          )}
         </section>
)}

<section className="panel" style={{ marginTop: 24 }}>
  <div
    style={{
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      gap: 12,
      flexWrap: "wrap",
    }}
  >
    <div>
      <small>DATABASE RECORDS</small>
      <h3>Recent Analyses</h3>
      <p>Previously saved indicator-analysis results.</p>
    </div>

    <button
      type="button"
      onClick={() => void loadHistory()}
      disabled={historyLoading}
      style={{
        padding: "9px 14px",
        border: "1px solid #334155",
        borderRadius: 8,
        background: "#1e293b",
        color: "#e2e8f0",
        cursor: historyLoading ? "wait" : "pointer",
      }}
    >
      {historyLoading ? "Refreshing..." : "Refresh"}
    </button>
  </div>

  {historyError && (
    <p role="alert" style={{ color: "#fca5a5" }}>
      {historyError}
    </p>
  )}

  {historyLoading && history.length === 0 && (
    <p>Loading analysis history...</p>
  )}

  {!historyLoading && !historyError && history.length === 0 && (
    <p>No saved analyses found. Analyze an indicator to get started.</p>
  )}

  {history.length > 0 && (
    <div style={{ overflowX: "auto", marginTop: 18 }}>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          textAlign: "left",
          fontSize: 13,
        }}
      >
        <thead>
          <tr>
            {["Indicator", "Type", "Verdict", "Risk", "Format", "Created"].map(
              (heading) => (
                <th
                  key={heading}
                  style={{
                    padding: 10,
                    borderBottom: "1px solid #334155",
                    color: "#94a3b8",
                    whiteSpace: "nowrap",
                  }}
                >
                  {heading}
                </th>
              )
            )}
          </tr>
        </thead>

        <tbody>
          {history.map((item) => (
            <tr key={item.id}>
              <td
                style={{
                  padding: 10,
                  borderBottom: "1px solid #1e293b",
                  overflowWrap: "anywhere",
                  maxWidth: 240,
                }}
              >
                {item.indicator}
              </td>
              <td style={{ padding: 10 }}>{item.indicator_type}</td>
              <td style={{ padding: 10 }}>{item.verdict}</td>
              <td style={{ padding: 10 }}>{item.risk_level}</td>
              <td style={{ padding: 10 }}>
                {item.format_valid ? "Valid" : "Invalid"}
              </td>
              <td style={{ padding: 10, whiteSpace: "nowrap" }}>
                {new Date(item.created_at).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )}
</section>

{/* Incident Management */}
<section
  id="incident-management"
  className="panel"
  style={{ marginTop: 24 }}
>
  <div
    style={{
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      flexWrap: "wrap",
      gap: 12,
    }}
  >
    <div>
      <small>SECURITY OPERATIONS</small>
      <h3>Incident Management</h3>
      <p>Create incidents, review investigations, and track response status.</p>
    </div>

    <button
      type="button"
      onClick={() => void loadIncidents()}
      disabled={incidentsLoading}
      style={fieldStyle}
    >
      {incidentsLoading ? "Refreshing..." : "Refresh incidents"}
    </button>
  </div>

  <div className="cards" style={{ marginTop: 18 }}>
    {[
      {
        label: "TOTAL SHOWN",
        value: incidents.length,
      },
      {
        label: "OPEN",
        value: incidents.filter((i) => i.status === "open").length,
      },
      {
        label: "HIGH / CRITICAL",
        value: incidents.filter(
          (i) => i.severity === "high" || i.severity === "critical"
        ).length,
      },
    ].map((item) => (
      <article key={item.label}>
        <small>{item.label}</small>
        <strong>{item.value}</strong>
      </article>
    ))}
  </div>
{canManageIncidents && (
  <>
  <h3 style={{ marginTop: 24 }}>Create incident</h3>

  <form
    onSubmit={createIncident}
    style={{ display: "grid", gap: 14 }}
  >
    <div>
      <label htmlFor="incidentTitle">Title</label>
      <input
        id="incidentTitle"
        value={incidentTitle}
        onChange={(e) => setIncidentTitle(e.target.value)}
        required
        minLength={3}
        maxLength={200}
        placeholder="Suspicious domain investigation"
        style={fieldStyle}
      />
    </div>

    <div>
      <label htmlFor="incidentDescription">Description</label>
      <textarea
        id="incidentDescription"
        value={incidentDescription}
        onChange={(e) => setIncidentDescription(e.target.value)}
        maxLength={2000}
        placeholder="Describe the alert and planned investigation."
        rows={3}
        style={fieldStyle}
      />
    </div>

    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
        gap: 14,
      }}
    >
      <div>
        <label htmlFor="incidentSeverity">Severity</label>
        <select
          id="incidentSeverity"
          value={incidentSeverity}
          onChange={(e) =>
            setIncidentSeverity(e.target.value as IncidentSeverity)
          }
          style={fieldStyle}
        >
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      <div>
        <label htmlFor="incidentIndicatorType">Indicator type</label>
        <select
          id="incidentIndicatorType"
          value={incidentIndicatorType}
          onChange={(e) =>
            setIncidentIndicatorType(e.target.value as IndicatorType)
          }
          style={fieldStyle}
        >
          <option value="domain">Domain</option>
          <option value="ip">IP address</option>
          <option value="url">URL</option>
          <option value="hash">File hash</option>
        </select>
      </div>
    </div>

    <div>
      <label htmlFor="incidentIndicator">Related indicator (optional)</label>
      <input
        id="incidentIndicator"
        value={incidentIndicator}
        onChange={(e) => setIncidentIndicator(e.target.value)}
        maxLength={2048}
        placeholder="example.com"
        autoComplete="off"
        style={fieldStyle}
      />
    </div>

    {incidentFormError && (
      <p role="alert" style={{ color: "#fca5a5" }}>
        {incidentFormError}
      </p>
    )}

    <button type="submit" disabled={incidentSaving}>
      {incidentSaving ? "Creating..." : "Create incident"}
    </button>
  </form>
  </>
)}
  <h3 style={{ marginTop: 30 }}>Incident register</h3>

  <div
    style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
      gap: 14,
      marginBottom: 16,
    }}
  >
    <div>
      <label htmlFor="incidentStatusFilter">Filter by status</label>
      <select
        id="incidentStatusFilter"
        value={incidentStatusFilter}
        onChange={(e) => setIncidentStatusFilter(e.target.value)}
        style={fieldStyle}
      >
        <option value="all">All statuses</option>
        <option value="open">Open</option>
        <option value="investigating">Investigating</option>
        <option value="resolved">Resolved</option>
        <option value="closed">Closed</option>
      </select>
    </div>

    <div>
      <label htmlFor="incidentSeverityFilter">Filter by severity</label>
      <select
        id="incidentSeverityFilter"
        value={incidentSeverityFilter}
        onChange={(e) => setIncidentSeverityFilter(e.target.value)}
        style={fieldStyle}
      >
        <option value="all">All severities</option>
        <option value="low">Low</option>
        <option value="medium">Medium</option>
        <option value="high">High</option>
        <option value="critical">Critical</option>
      </select>
    </div>
  </div>

  {incidentsError && (
    <p role="alert" style={{ color: "#fca5a5" }}>
      {incidentsError}
    </p>
  )}

  {incidentsLoading && <p>Loading incidents...</p>}

  {!incidentsLoading && !incidentsError && incidents.length === 0 && (
    <p>No incidents found for the selected filters.</p>
  )}

  {incidents.length > 0 && (
    <div style={{ overflowX: "auto" }}>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          textAlign: "left",
          fontSize: 13,
        }}
      >
        <thead>
          <tr>
            {["Incident", "Severity", "Status", "Indicator", "Created", "Update status"].map(
              (heading) => (
                <th
                  key={heading}
                  style={{
                    padding: 10,
                    borderBottom: "1px solid #334155",
                    color: "#94a3b8",
                    whiteSpace: "nowrap",
                  }}
                >
                  {heading}
                </th>
              )
            )}
          </tr>
        </thead>

        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.id}>
              <td style={{ padding: 10, minWidth: 180 }}>
                <strong>{incident.title}</strong>
                <p style={{ color: "#94a3b8", overflowWrap: "anywhere" }}>
                  {incident.description || "No description"}
                </p>
                <small>INC-{incident.id}</small>
              </td>

              <td style={{ padding: 10 }}>{incident.severity}</td>
              <td style={{ padding: 10 }}>{incident.status}</td>
              <td style={{ padding: 10 }}>
              <button
                type="button"
                onClick={() => void openIncident(incident)}
                style={{
                     ...fieldStyle,
                    cursor: "pointer",
                fontWeight: 600,
                 whiteSpace: "nowrap",
                          }}
                      >
                      View Details
                          </button>
                         </td>

              <td style={{ padding: 10, overflowWrap: "anywhere" }}>
                {incident.indicator
                  ? `${incident.indicator_type ?? "indicator"}: ${incident.indicator}`
                  : "—"}
              </td>

              <td style={{ padding: 10, whiteSpace: "nowrap" }}>
                {new Date(incident.created_at).toLocaleString()}
              </td>

              <td style={{ padding: 10, minWidth: 160 }}>
                <select
                  aria-label={`Update status for incident ${incident.id}`}
                  value={incident.status}
                  onChange={(e) =>
                    void updateIncidentStatus(
                      incident.id,
                      e.target.value as IncidentStatus
                    )
                  }
                  style={fieldStyle}
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )}

</section>

{/* Incident Investigation Detail Panel */}
{selectedIncident && (
  <section className="panel" style={{ marginTop: 24 }}>
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: 12,
      }}
    >
      <div>
        <small>SECURITY OPERATIONS / INVESTIGATION</small>
        <h3>{selectedIncident.title}</h3>
        <p>INC-{selectedIncident.id}</p>
      </div>

      <button
        type="button"
        onClick={() => setSelectedIncident(null)}
        style={fieldStyle}
      >
        Close Details
      </button>
    </div>

    {investigationError && (
      <p role="alert" style={{ color: "#fca5a5" }}>
        {investigationError}
      </p>
    )}

    {investigationLoading ? (
      <p>Loading investigation details...</p>
    ) : (
      <>
        {/* Incident Overview */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
            gap: 12,
            marginTop: 20,
          }}
        >
          <div>
            <small>SEVERITY</small>
            <h4>{selectedIncident.severity.toUpperCase()}</h4>
          </div>

          <div>
            <small>STATUS</small>
            <h4>{selectedIncident.status.toUpperCase()}</h4>
          </div>

          <div>
            <small>INDICATOR</small>
            <p style={{ overflowWrap: "anywhere" }}>
              {selectedIncident.indicator || "Not available"}
            </p>
          </div>
        </div>

        {/* Evidence Viewer */}
        <div style={{ marginTop: 24 }}>
          <h4>Analysis Evidence</h4>
          <pre
            style={{
              ...fieldStyle,
              whiteSpace: "pre-wrap",
              overflowWrap: "anywhere",
              maxHeight: 350,
              overflowY: "auto",
            }}
          >
            {formatValue(selectedIncident.evidence)}
          </pre>
        </div>

{/* Incident Assignment and Resolution Management */}
<div style={{ marginTop: 24 }}>
  <h4>Incident Assignment & Resolution</h4>

  <div style={{ display: "grid", gap: 14 }}>

    <div>
      <label htmlFor="assignedTo">Assigned Analyst</label>
      <input
        id="assignedTo"
        value={assignedTo}
        onChange={(e) => setAssignedTo(e.target.value)}
        maxLength={100}
        placeholder="Enter analyst name"
        style={fieldStyle}
      />
    </div>

    <div>
      <label htmlFor="rootCause">Root Cause</label>
      <textarea
        id="rootCause"
        value={rootCause}
        onChange={(e) => setRootCause(e.target.value)}
        maxLength={10000}
        rows={3}
        placeholder="Describe the root cause..."
        style={fieldStyle}
      />
    </div>

    <div>
      <label htmlFor="resolutionSummary">
        Resolution Summary
      </label>
      <textarea
        id="resolutionSummary"
        value={resolutionSummary}
        onChange={(e) => setResolutionSummary(e.target.value)}
        maxLength={10000}
        rows={3}
        placeholder="Describe the resolution actions..."
        style={fieldStyle}
      />
    </div>

    <button
      type="button"
      disabled={incidentUpdateSaving}
      onClick={() => void saveIncidentManagementDetails()}
      style={{
        ...fieldStyle,
        cursor: "pointer",
        fontWeight: 600,
        opacity: incidentUpdateSaving ? 0.6 : 1,
      }}
    >
      {incidentUpdateSaving
        ? "Saving..."
        : "Save Incident Details"}
    </button>

    <div>
      <p>
        <strong>Resolved at:</strong>{" "}
        {selectedIncident.resolved_at
          ? new Date(selectedIncident.resolved_at).toLocaleString()
          : "Not resolved"}
      </p>

      <p>
        <strong>Closed at:</strong>{" "}
        {selectedIncident.closed_at
          ? new Date(selectedIncident.closed_at).toLocaleString()
          : "Not closed"}
      </p>
    </div>

  </div>
</div>

        {/* Investigation Timeline */}
        <div style={{ marginTop: 24 }}>
          <h4>Investigation Timeline</h4>

          {incidentActivities.length === 0 ? (
            <p>No investigation activities recorded yet.</p>
          ) : (
            <div style={{ display: "grid", gap: 12 }}>
              {incidentActivities.map((activity) => (
                <div
                  key={activity.id}
                  style={{
                    borderLeft: "3px solid #38bdf8",
                    padding: "10px 14px",
                    background: "#0f172a",
                    borderRadius: 6,
                  }}
                >
                  <strong>{activity.action}</strong>
                  <p>{activity.description}</p>
                  <small>
                    {activity.actor} ·{" "}
                    {new Date(activity.created_at).toLocaleString()}
                  </small>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Analyst Notes */}
        <div style={{ marginTop: 24 }}>
          <h4>Analyst Notes</h4>

          <textarea
            value={newNote}
            onChange={(e) => setNewNote(e.target.value)}
            placeholder="Enter investigation observations..."
            rows={4}
            style={fieldStyle}
          />

          <button
            type="button"
            disabled={noteSaving || !newNote.trim()}
            onClick={() => void submitInvestigationNote()}
            style={{
              ...fieldStyle,
              marginTop: 10,
              cursor: "pointer",
              fontWeight: 600,
              opacity: noteSaving || !newNote.trim() ? 0.6 : 1,
            }}
          >
            {noteSaving ? "Saving..." : "Add Investigation Note"}
          </button>

          <div style={{ display: "grid", gap: 12, marginTop: 18 }}>
            {incidentNotes.map((note) => (
              <div
                key={note.id}
                style={{
                  padding: 14,
                  background: "#0f172a",
                  border: "1px solid #334155",
                  borderRadius: 8,
                }}
              >
                <p style={{ whiteSpace: "pre-wrap" }}>{note.note}</p>
                <small>
                  {note.author} ·{" "}
                  {new Date(note.created_at).toLocaleString()}
                </small>
              </div>
            ))}
          </div>
        </div>
      </>
    )}
  </section>
)}

<section className="panel" style={{ marginTop: 24 }}>
  <small>FIRST MILESTONE</small>

          <h3>Foundation checklist</h3>

          <div className="row">
            <b className="done">✓</b>
            <div>
              <strong>Frontend scaffold</strong>
              <p>React + TypeScript is rendering locally.</p>
            </div>
            <em>READY</em>
          </div>

          <div className="row">
            <b className={health?.status === "ok" ? "done" : ""}>
              2
            </b>
            <div>
              <strong>API health endpoint</strong>
              <p>
                {health?.status === "ok"
                  ? "FastAPI responded successfully."
                  : error || "Waiting for FastAPI."}
              </p>
            </div>
            <em>{health?.status === "ok" ? "READY" : "PENDING"}</em>
          </div>

          <div className="row">
            <b>3</b>
            <div>
              <strong>PostgreSQL connection</strong>
              <p>Configure database access and migrations.</p>
            </div>
            <em>NEXT</em>
          </div>

          <div className="row">
            <b className={result ? "done" : ""}>4</b>
            <div>
              <strong>Safe indicator analysis</strong>
              <p>
                {result
                  ? "The analysis endpoint returned a response."
                  : "Validate and analyze user-supplied indicators."}
              </p>
            </div>
            <em>{result ? "READY" : "IN PROGRESS"}</em>
          </div>
        </section>
  </>
)}
{activePage === "users" && isAdmin && (
  <section className="panel" style={{ marginTop: 24 }}>
    <div className="panel-heading">
      <div>
        <p className="label">ADMINISTRATION</p>
        <h2>User Management</h2>
        <p>Manage platform accounts, roles, and access status.</p>
      </div>

      <button
        className="primary-button"
        onClick={() => {
          setShowCreateUser((previous) => !previous);
          setUsersError("");
          setUsersSuccess("");
        }}
      >
        {showCreateUser ? "Cancel" : "Create User"}
      </button>
    </div>

    {usersLoading && <p>Loading users...</p>}

    {usersError && (
      <p style={{ color: "#dc2626" }}>{usersError}</p>
    )}

    {usersSuccess && (
      <p style={{ color: "#16a34a" }}>{usersSuccess}</p>
    )}
{showCreateUser && (
  <form
    onSubmit={handleCreateUser}
    style={{
      display: "grid",
      gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
      gap: 14,
      padding: 20,
      marginBottom: 20,
      border: "1px solid #334155",
      borderRadius: 12,
    }}
  >
    <input
      type="text"
      placeholder="Username"
      value={newUsername}
      onChange={(event) => setNewUsername(event.target.value)}
      minLength={3}
      required
    />

    <input
      type="email"
      placeholder="Email address"
      value={newEmail}
      onChange={(event) => setNewEmail(event.target.value)}
      required
    />

    <input
      type="password"
      placeholder="Password (minimum 8 characters)"
      value={newPassword}
      onChange={(event) => setNewPassword(event.target.value)}
      minLength={8}
      required
    />

    <select
      value={newUserRole}
      onChange={(event) =>
        setNewUserRole(event.target.value as UserRole)
      }
    >
      <option value="analyst">Analyst</option>
      <option value="viewer">Viewer</option>
      <option value="admin">Admin</option>
    </select>

    <button
      type="submit"
      disabled={userSaving}
      className="primary-button"
      style={{ gridColumn: "1 / -1" }}
    >
      {userSaving ? "Creating..." : "Create Account"}
    </button>
  </form>
)}
    <div style={{ display: "flex", gap: 12, margin: "20px 0" }}>
      <input
        type="text"
        placeholder="Search username or email..."
        value={userSearch}
        onChange={(event) => setUserSearch(event.target.value)}
      />

      <select
        value={userRoleFilter}
        onChange={(event) => setUserRoleFilter(event.target.value)}
      >
        <option value="all">All roles</option>
        <option value="admin">Admin</option>
        <option value="analyst">Analyst</option>
        <option value="viewer">Viewer</option>
      </select>
    </div>

    <p>Total users: {adminUsers.length}</p>

    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>

        <tbody>
          {adminUsers
            .filter((user) => {
              const search = userSearch.toLowerCase();

              const matchesSearch =
                user.username.toLowerCase().includes(search) ||
                user.email.toLowerCase().includes(search);

              const matchesRole =
                userRoleFilter === "all" ||
                user.role === userRoleFilter;

              return matchesSearch && matchesRole;
            })
            .map((user) => {
              const isCurrentUser = user.id === currentUser?.id;

              return (
                <tr key={user.id}>
                  <td>{user.username}</td>
                  <td>{user.email}</td>

                  <td>
                    <select
                      value={user.role}
                      disabled={isCurrentUser || editingUserId === user.id}
                      onChange={(event) =>
                        handleRoleUpdate(
                          user.id,
                          event.target.value as UserRole
                        )
                      }
                    >
                      <option value="admin">Admin</option>
                      <option value="analyst">Analyst</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </td>

                  <td>
                    <span>
                      {user.is_active ? "Active" : "Inactive"}
                    </span>
                  </td>

                  <td>
                    <button
                      disabled={isCurrentUser || editingUserId === user.id}
                      onClick={() =>
                        handleUserStatus(user.id, !user.is_active)
                      }
                    >
                      {user.is_active ? "Deactivate" : "Activate"}
                    </button>

                    <button
                      disabled={isCurrentUser || editingUserId === user.id}
                      onClick={() => handleDeleteUser(user.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              );
            })}
        </tbody>
      </table>
    </div>
  </section>
)}
{activePage === "audit-logs" && isAdmin && (
  <section className="panel" style={{ marginTop: 24 }}>
    <div className="panel-heading">
      <div>
        <p className="label">SECURITY MONITORING</p>
        <h2>Audit Logs</h2>
        <p>
          Review administrative activities and security-related events.
        </p>
      </div>

      <div style={{ display: "flex", gap: 10 }}>
  <button
    className="primary-button"
    onClick={() => void loadAuditLogs()}
    disabled={auditLogsLoading}
  >
    {auditLogsLoading ? "Refreshing..." : "Refresh Logs"}
  </button>

  <button
    className="primary-button"
    onClick={exportAuditLogsCSV}
    disabled={auditLogs.length === 0}
  >
    Export CSV
  </button>
</div>
    </div>

    {/* Action filter */}
    <div
      style={{
        display: "flex",
        gap: 12,
        margin: "20px 0",
        flexWrap: "wrap",
      }}
    >
      <select
        value={auditLogActionFilter}
        onChange={(event) => setAuditLogActionFilter(event.target.value)}
      >
        <option value="">All actions</option>
        <option value="LOGIN_SUCCESS">Login Success</option>
        <option value="LOGIN_FAILED">Login Failed</option>
        <option value="LOGIN_BLOCKED">Login Blocked</option>
        <option value="INCIDENT_CREATED">Incident Created</option>
        <option value="INCIDENT_UPDATED">Incident Updated</option>
        <option value="INCIDENT_DELETED">Incident Deleted</option>
        <option value="ALERT_CREATED">Alert Created</option>
        <option value="ALERT_UPDATED">Alert Updated</option>
        <option value="PCAP_ANALYZED">PCAP Analyzed</option>
        <option value="NETWORK_ANOMALIES_DETECTED">
          Network Anomalies Detected
        </option>
        <option value="AI_ANALYSIS_REPORT_GENERATED">
          AI Report Generated
        </option>
        <option value="ADMIN_USER_CREATED">Admin User Created</option>
        <option value="ADMIN_USER_UPDATED">Admin User Updated</option>
        <option value="ADMIN_USER_DELETED">Admin User Deleted</option>
      </select>
    </div>

    {auditLogsError && (
      <p role="alert" style={{ color: "#ef4444" }}>
        {auditLogsError}
      </p>
    )}

    {auditLogsLoading && <p>Loading audit logs...</p>}

    {!auditLogsLoading && !auditLogsError && auditLogs.length === 0 && (
      <p>No audit logs found.</p>
    )}

    {auditLogs.length > 0 && (
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>User</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Resource ID</th>
              <th>IP Address</th>
              <th>Details</th>
            </tr>
          </thead>

          <tbody>
            {auditLogs.map((log) => (
              <tr key={log.id}>
                <td>
                  {log.created_at
                    ? new Date(log.created_at).toLocaleString()
                    : "—"}
                </td>
                <td>{log.username}</td>
                <td>{log.action}</td>
                <td>{log.resource_type ?? "—"}</td>
                <td>{log.resource_id ?? "—"}</td>
                <td>{log.ip_address ?? "—"}</td>
                <td>
                  <span title={JSON.stringify(log.details)}>
                    {JSON.stringify(log.details).slice(0, 80) || "—"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </section>
)}
{activePage === "alerts" && (
  <section className="panel" style={{ marginTop: 24 }}>
    <div className="panel-heading">
      <div>
        <p className="label">SECURITY MONITORING</p>
        <h2>Security Alerts</h2>
        <p>Monitor, investigate, and manage detected security threats.</p>
      </div>

      <button
        className="primary-button"
        onClick={() => void loadAlerts()}
        disabled={alertsLoading}
      >
        {alertsLoading ? "Refreshing..." : "Refresh Alerts"}
      </button>
    </div>

    {/* Alert summary */}
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
        gap: 12,
        margin: "20px 0",
      }}
    >
      <div className="panel">
        <p>Total Alerts</p>
        <h2>{alerts.length}</h2>
      </div>

      <div className="panel">
        <p>Critical Alerts</p>
        <h2>
          {alerts.filter((a) => a.severity === "critical").length}
        </h2>
      </div>

      <div className="panel">
        <p>New Alerts</p>
        <h2>{alerts.filter((a) => a.status === "new").length}</h2>
      </div>

      <div className="panel">
        <p>Investigating</p>
        <h2>
          {alerts.filter((a) => a.status === "investigating").length}
        </h2>
      </div>
    </div>

    {/* Search and filters */}
    <div
      style={{
        display: "flex",
        gap: 12,
        margin: "20px 0",
        flexWrap: "wrap",
      }}
    >
      <input
        type="text"
        placeholder="Search alerts..."
        value={alertSearch}
        onChange={(event) => setAlertSearch(event.target.value)}
      />

      <select
        value={alertSeverityFilter}
        onChange={(event) =>
          setAlertSeverityFilter(event.target.value as AlertSeverity | "")
        }
      >
        <option value="">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>

      <select
        value={alertStatusFilter}
        onChange={(event) =>
          setAlertStatusFilter(event.target.value as AlertStatus | "")
        }
      >
        <option value="">All statuses</option>
        <option value="new">New</option>
        <option value="acknowledged">Acknowledged</option>
        <option value="investigating">Investigating</option>
        <option value="resolved">Resolved</option>
      </select>
    </div>

    {alertsError && (
      <p style={{ color: "#dc2626" }}>{alertsError}</p>
    )}

    {alertsLoading && <p>Loading security alerts...</p>}

    {!alertsLoading && alerts.length === 0 && (
      <p>No security alerts found.</p>
    )}

    {/* Alert table */}
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Alert</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Risk Score</th>
            <th>Indicator</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>

        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td>
                <strong>{alert.title}</strong>
                <p style={{ fontSize: 12 }}>
                  ID: {alert.id}
                </p>
              </td>

              <td>{alert.source}</td>

              <td>
                <strong
                  style={{
                    color:
                      alert.severity === "critical"
                        ? "#dc2626"
                        : alert.severity === "high"
                          ? "#ea580c"
                          : alert.severity === "medium"
                            ? "#ca8a04"
                            : "#16a34a",
                  }}
                >
                  {alert.severity.toUpperCase()}
                </strong>
              </td>

              <td>{alert.status.toUpperCase()}</td>

              <td>{alert.risk_score ?? "N/A"}</td>

              <td>
                {alert.indicator
                  ? `${alert.indicator_type ?? "unknown"}: ${alert.indicator}`
                  : "N/A"}
              </td>

              <td>
                {new Date(alert.created_at).toLocaleString()}
              </td>

              <td>
                {alert.status === "new" && (
                  <button
                    onClick={() =>
                      void handleAcknowledgeAlert(alert.id)
                    }
                  >
                    Acknowledge
                  </button>
                )}

                {!alert.incident_id && (
                  <button
                    onClick={() => void handleConvertAlert(alert.id)}
                  >
                    Convert to Incident
                  </button>
                )}

                {alert.incident_id && (
                  <span>Incident #{alert.incident_id}</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </section>
)}
{activePage === "network" && (
  <section className="panel" style={{ marginTop: 24 }}>
    <div className="panel-heading">
      <div>
        <p className="label">NETWORK SECURITY</p>
        <h2>Network Traffic Analysis</h2>
        <p>Upload a PCAP capture to inspect network flows and protocols.</p>
      </div>
    </div>

    {/* PCAP upload */}
    <div className="panel" style={{ marginTop: 20 }}>
      <h3>Upload PCAP File</h3>

      <input
        type="file"
        accept=".pcap,.cap"
        onChange={(event) => {
          setPcapFile(event.target.files?.[0] ?? null);
          setNetworkError("");
          setNetworkAnalysis(null);
        }}
      />

      <button
        className="primary-button"
        onClick={() => void handlePcapAnalysis()}
        disabled={!pcapFile || networkLoading}
        style={{ marginLeft: 12 }}
      >
        {networkLoading ? "Analyzing..." : "Analyze Network Traffic"}
      </button>

      {pcapFile && (
        <p style={{ marginTop: 10 }}>
          Selected file: <strong>{pcapFile.name}</strong>
        </p>
      )}

      {networkError && (
        <p style={{ color: "#dc2626", marginTop: 12 }}>
          {networkError}
        </p>
      )}
    </div>

    {/* Analysis results */}
    {networkAnalysis && (
      <>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
            gap: 12,
            margin: "20px 0",
          }}
        >
          <div className="panel">
            <p>Total Packets</p>
            <h2>{networkAnalysis.packet_count}</h2>
          </div>

          <div className="panel">
            <p>Total Flows</p>
            <h2>{networkAnalysis.flow_count}</h2>
          </div>

          <div className="panel">
            <p>TCP Flows</p>
            <h2>
              {networkAnalysis.flows.filter(
                (flow) => flow.protocol === "TCP"
              ).length}
            </h2>
          </div>

          <div className="panel">
            <p>UDP Flows</p>
            <h2>
              {networkAnalysis.flows.filter(
                (flow) => flow.protocol === "UDP"
              ).length}
            </h2>
          </div>
        </div>

        <p>
          File size:{" "}
          {(networkAnalysis.file_size_bytes / 1024).toFixed(2)} KB
        </p>

        {/* Search and protocol filter */}
        <div
          style={{
            display: "flex",
            gap: 12,
            margin: "20px 0",
            flexWrap: "wrap",
          }}
        >
          <input
            type="text"
            placeholder="Search IP address..."
            value={networkSearch}
            onChange={(event) => setNetworkSearch(event.target.value)}
          />

          <select
            value={networkProtocolFilter}
            onChange={(event) =>
              setNetworkProtocolFilter(
                event.target.value as "all" | "TCP" | "UDP"
              )
            }
          >
            <option value="all">All protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
          </select>
        </div>

        {/* Network flows table */}
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Source Port</th>
                <th>Destination Port</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Duration</th>
                <th>TCP Flags</th>
              </tr>
            </thead>

            <tbody>
              {networkAnalysis.flows
                .filter((flow) => {
                  const search = networkSearch.toLowerCase();

                  const matchesSearch =
                    flow.source_ip.toLowerCase().includes(search) ||
                    flow.destination_ip.toLowerCase().includes(search);

                  const matchesProtocol =
                    networkProtocolFilter === "all" ||
                    flow.protocol === networkProtocolFilter;

                  return matchesSearch && matchesProtocol;
                })
                .map((flow) => (
                  <tr key={flow.id}>
                    <td>{flow.source_ip}</td>
                    <td>{flow.destination_ip}</td>
                    <td>{flow.protocol}</td>
                    <td>{flow.source_port ?? "N/A"}</td>
                    <td>{flow.destination_port ?? "N/A"}</td>
                    <td>{flow.packet_count}</td>
                    <td>{flow.byte_count}</td>
                    <td>{flow.duration_seconds.toFixed(3)} s</td>
                    <td>{flow.tcp_flags ?? "N/A"}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>

        {networkAnalysis.flows.length === 0 && (
          <p>No TCP or UDP network flows were detected.</p>
        )}
      </>
    )}
  </section>
)}
{activePage === "anomalies" && (
  <section className="panel" style={{ marginTop: 24 }}>
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: 16,
        flexWrap: "wrap",
      }}
    >
      <div>
        <h2>Network Anomaly Detection</h2>
        <p>
          Detect unusual network traffic patterns using the trained
          Isolation Forest model.
        </p>
      </div>

      <button
        onClick={handleDetectAnomalies}
        disabled={anomalyDetectionLoading}
        style={{
          padding: "11px 18px",
          borderRadius: 8,
          border: "none",
          cursor: anomalyDetectionLoading ? "not-allowed" : "pointer",
          opacity: anomalyDetectionLoading ? 0.6 : 1,
        }}
      >
        {anomalyDetectionLoading
          ? "Analyzing Network Traffic..."
          : "Run Anomaly Detection"}
      </button>
    </div>

    {anomalyError && (
      <div style={{ color: "#dc2626", marginTop: 16 }}>
        <AlertCircle size={16} style={{ verticalAlign: "middle" }} />{" "}
        {anomalyError}
      </div>
    )}

    {anomalyDetectionResult && (
      <div style={{ marginTop: 24 }}>
        <h3>Latest Detection Results</h3>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
            gap: 16,
          }}
        >
          <div className="stat-card">
            <p>Total Flows Analyzed</p>
            <h2>{anomalyDetectionResult.total_flows_analyzed}</h2>
          </div>

          <div className="stat-card">
            <p>Anomalies Detected</p>
            <h2>{anomalyDetectionResult.anomalies_detected}</h2>
          </div>

          <div className="stat-card">
            <p>Anomalies Saved</p>
            <h2>{anomalyDetectionResult.anomalies_saved}</h2>
          </div>
        </div>
      </div>
    )}


    <div style={{ marginTop: 28 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <h3>Detected Anomaly History</h3>

        <button
          onClick={() => void loadNetworkAnomalies()}
          disabled={anomalyHistoryLoading}
        >
          {anomalyHistoryLoading ? "Refreshing..." : "Refresh History"}
        </button>
      </div>

      {anomalyHistoryLoading ? (
        <p>
          <LoaderCircle size={16} /> Loading anomaly history...
        </p>
      ) : networkAnomalies.length === 0 ? (
        <p>No anomaly records found.</p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left", padding: 12 }}>ID</th>
                <th style={{ textAlign: "left", padding: 12 }}>Flow ID</th>
                <th style={{ textAlign: "left", padding: 12 }}>Source IP</th>
                <th style={{ textAlign: "left", padding: 12 }}>Destination IP</th>
                <th style={{ textAlign: "left", padding: 12 }}>Protocol</th>
                <th style={{ textAlign: "left", padding: 12 }}>Anomaly Score</th>
                <th style={{ textAlign: "left", padding: 12 }}>Model</th>
                <th style={{ textAlign: "left", padding: 12 }}>Detected At</th>
              </tr>
            </thead>

            <tbody>
              {networkAnomalies.map((anomaly) => (
                <tr key={anomaly.id}>
                  <td style={{ padding: 12 }}>{anomaly.id}</td>
                  <td style={{ padding: 12 }}>
                    {anomaly.flow_id ?? "N/A"}
                  </td>
                  <td style={{ padding: 12 }}>{anomaly.source_ip}</td>
                  <td style={{ padding: 12 }}>{anomaly.destination_ip}</td>
                  <td style={{ padding: 12 }}>{anomaly.protocol}</td>
                  <td style={{ padding: 12 }}>
                    {anomaly.anomaly_score.toFixed(4)}
                  </td>
                  <td style={{ padding: 12 }}>{anomaly.model_name}</td>
                  <td style={{ padding: 12 }}>
                    {new Date(anomaly.detected_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  </section>
)}
 {activePage === "ai-analysis" && (
  <section className="section">
    <div className="section-header">
      <div>
        <h2>AI Security Analysis</h2>
        <p>
          Generate AI-assisted security reports from incident evidence.
        </p>
      </div>
    </div>

    {canAnalyze && (
      <div className="card" style={{ marginBottom: "20px" }}>
        <h3>Generate New Analysis</h3>

        <label style={{ display: "block", marginBottom: "8px" }}>
          Select Incident
        </label>

        <select
          value={aiSelectedIncidentId}
          onChange={(event) => setAiSelectedIncidentId(event.target.value)}
          style={{ ...fieldStyle, width: "100%", marginBottom: "12px" }}
        >
          <option value="">Choose an incident</option>
          {incidents.map((incident) => (
            <option key={incident.id} value={incident.id}>
              #{incident.id} — {incident.title}
            </option>
          ))}
        </select>

        <button
          onClick={generateAIReport}
          disabled={!aiSelectedIncidentId || aiGenerating}
        >
          {aiGenerating ? "Generating..." : "Generate AI Report"}
        </button>
      </div>
    )}

    {aiAnalysisError && (
      <div className="card" style={{ marginBottom: "16px" }}>
        <p style={{ color: "#f87171" }}>{aiAnalysisError}</p>
      </div>
    )}

    <div className="card">
      <h3>Report History</h3>

      {aiHistoryLoading ? (
        <p>Loading report history...</p>
      ) : aiReportHistory.length === 0 ? (
        <p>No AI reports have been generated yet.</p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>Report ID</th>
                <th>Incident</th>
                <th>Severity</th>
                <th>Threat Category</th>
                <th>Generated</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {aiReportHistory.map((report) => (
                <tr key={report.report_id}>
                  <td>#{report.report_id}</td>
                  <td>{report.incident_id ?? "—"}</td>
                  <td>{report.severity}</td>
                  <td>{report.threat_category}</td>
                  <td>{new Date(report.created_at).toLocaleString()}</td>
                  <td>
                    <button
                      onClick={() => loadAIReportDetail(report.report_id)}
                    >
                      View Report
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>

    {aiDetailLoading && (
      <div className="card" style={{ marginTop: "20px" }}>
        <p>Loading report details...</p>
      </div>
    )}

    {selectedAIReport && (
      <div className="card" style={{ marginTop: "20px" }}>
        <h3>AI Analysis Report #{selectedAIReport.report_id}</h3>

        <p>
          <strong>Model:</strong> {selectedAIReport.model_name}
        </p>
        <p>
          <strong>Generated:</strong>{" "}
          {new Date(selectedAIReport.created_at).toLocaleString()}
        </p>
        <p>
          <strong>Severity:</strong> {selectedAIReport.report.severity}
        </p>
        <p>
          <strong>Confidence:</strong> {selectedAIReport.report.confidence}
        </p>
        <p>
          <strong>Threat Category:</strong>{" "}
          {selectedAIReport.report.threat_category}
        </p>

        <h4>Executive Summary</h4>
        <p>{selectedAIReport.report.executive_summary}</p>

        <h4>Key Findings</h4>
        <ul>
          {selectedAIReport.report.key_findings.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>

        <h4>Evidence Assessment</h4>
        <ul>
          {selectedAIReport.report.evidence_assessment.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>

        <h4>Recommended Actions</h4>
        <ul>
          {selectedAIReport.report.recommended_actions.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>

        <h4>Limitations</h4>
        <ul>
          {selectedAIReport.report.limitations.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>

        <h4>Evidence Snapshot</h4>
        <pre style={{ overflowX: "auto", whiteSpace: "pre-wrap" }}>
          {JSON.stringify(selectedAIReport.evidence_snapshot, null, 2)}
        </pre>
      </div>
    )}
  </section>
)}

        <footer className="bottom">
          READ-ONLY BY DESIGN <span>Local prototype</span>
        </footer>
      </section>
    </main>
  );
}
