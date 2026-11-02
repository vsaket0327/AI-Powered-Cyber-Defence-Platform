const API_BASE = "http://127.0.0.1:8000";

export type UserRole = "admin" | "analyst" | "viewer";

export type AuthUser = {
  id: number;
  username: string;
  email: string;
  role: UserRole;
};

export type LoginResponse = {
  access_token: string;
  token_type: string;
  user: AuthUser;
};

const TOKEN_KEY = "cyberguard_access_token";
const USER_KEY = "cyberguard_user";

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function getUser(): AuthUser | null {
  const storedUser = sessionStorage.getItem(USER_KEY);

  if (!storedUser) return null;

  try {
    return JSON.parse(storedUser) as AuthUser;
  } catch {
    sessionStorage.removeItem(USER_KEY);
    return null;
  }
}

export async function login(
  usernameOrEmail: string,
  password: string
): Promise<LoginResponse> {
  const response = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username_or_email: usernameOrEmail,
      password,
    }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.detail ?? "Login failed.");
  }

  const result = data as LoginResponse;

  sessionStorage.setItem(TOKEN_KEY, result.access_token);
  sessionStorage.setItem(USER_KEY, JSON.stringify(result.user));

  return result;
}

export function logout(): void {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USER_KEY);
}

export async function apiFetch(
  input: RequestInfo | URL,
  init: RequestInit = {}
): Promise<Response> {
  const token = getToken();

  const headers = new Headers(init.headers);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return fetch(input, {
    ...init,
    headers,
  });
}

export type AdminUser = {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string | null;
};

export type AdminUsersResponse = {
  count: number;
  items: AdminUser[];
};

export type AdminUserCreatePayload = {
  username: string;
  email: string;
  password: string;
  role: UserRole;
};

export type AdminUserUpdatePayload = {
  role?: UserRole;
  is_active?: boolean;
};

async function getApiError(response: Response): Promise<string> {
  try {
    const data = await response.json();
    return data.detail ?? `Request failed: ${response.status}`;
  } catch {
    return `Request failed: ${response.status}`;
  }
}

// Fetch all registered users
export async function getAdminUsers(): Promise<AdminUsersResponse> {
  const response = await apiFetch(
    `${API_BASE}/api/v1/admin/users`
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}

// Create a new user
export async function createAdminUser(
  payload: AdminUserCreatePayload
) {
  const response = await apiFetch(
    `${API_BASE}/api/v1/admin/users`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}

// Update user role or account status
export async function updateAdminUser(
  userId: number,
  payload: AdminUserUpdatePayload
) {
  const response = await apiFetch(
    `${API_BASE}/api/v1/admin/users/${userId}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}

// Delete a user
export async function deleteAdminUser(
  userId: number
): Promise<void> {
  const response = await apiFetch(
    `${API_BASE}/api/v1/admin/users/${userId}`,
    {
      method: "DELETE",
    }
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }
}
// ===============================
// SECURITY ALERT MANAGEMENT
// ===============================

export type AlertSeverity =
  | "low"
  | "medium"
  | "high"
  | "critical";

export type AlertStatus =
  | "new"
  | "acknowledged"
  | "investigating"
  | "resolved";

export type SecurityAlert = {
  id: number;
  title: string;
  description: string;
  source: string;
  severity: AlertSeverity;
  status: AlertStatus;
  indicator_type: "ip" | "domain" | "url" | "hash" | null;
  indicator: string | null;
  risk_score: number | null;
  evidence: Record<string, unknown>;
  assigned_to: string | null;
  incident_id: number | null;
  created_at: string;
  updated_at: string;
};

export type AlertsResponse = {
  count: number;
  items: SecurityAlert[];
};

export type AlertUpdatePayload = {
  severity?: AlertSeverity;
  status?: AlertStatus;
  assigned_to?: string;
};
// Fetch alerts with optional filters
export async function getAlerts(
  filters: {
    severity?: string;
    status?: string;
    search?: string;
    skip?: number;
    limit?: number;
  } = {}
): Promise<AlertsResponse> {
  const params = new URLSearchParams();

  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== "") {
      params.set(key, String(value));
    }
  });

  const response = await apiFetch(
    `${API_BASE}/api/v1/alerts?${params.toString()}`
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}

// Update alert status, severity or assignment
export async function updateAlert(
  alertId: number,
  payload: AlertUpdatePayload
): Promise<AlertUpdateResponse> {
  const response = await apiFetch(
    `${API_BASE}/api/v1/alerts/${alertId}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}
export type AlertUpdateResponse = {
  message: string;
  alert_id: number;
  severity: AlertSeverity;
  status: AlertStatus;
  assigned_to: string | null;
};

// Convert an alert into an incident
export async function convertAlertToIncident(
  alertId: number
): Promise<{
  message: string;
  alert_id: number;
  incident_id: number;
}> {
  const response = await apiFetch(
    `${API_BASE}/api/v1/alerts/${alertId}/convert-to-incident`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}

export type NetworkFlow = {
  id: number;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: "TCP" | "UDP";
  packet_count: number;
  byte_count: number;
  start_time: string;
  end_time: string;
  duration_seconds: number;
  tcp_flags: string | null;
};

export type PcapAnalysisResponse = {
  message: string;
  file_size_bytes: number;
  packet_count: number;
  flow_count: number;
  flows: NetworkFlow[];
};

// Upload and analyze a PCAP file
export async function analyzePcap(
  file: File
): Promise<PcapAnalysisResponse> {
  const formData = new FormData();

  formData.append("file", file);

  const response = await apiFetch(
    `${API_BASE}/api/v1/network/analyze-pcap`,
    {
      method: "POST",
      body: formData,
    }
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}
// ===============================
// ML ANOMALY DETECTION
// ===============================

export type NetworkAnomaly = {
  id: number;
  flow_id: number | null;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  anomaly_score: number;
  status: string;
  model_name: string;
  detected_at: string;
};

export type AnomalyHistoryResponse = {
  total: number;
  anomalies: NetworkAnomaly[];
};

export type AnomalyDetectionResponse = {
  message: string;
  total_flows_analyzed: number;
  anomalies_detected: number;
  anomalies_saved: number;
  anomalies: {
    flow_id: number;
    source_ip: string;
    destination_ip: string;
    protocol: string;
    is_anomaly: boolean;
    anomaly_score: number;
    status: string;
  }[];
};

// Retrieve previously detected anomalies
export async function getNetworkAnomalies(
  limit = 100,
  offset = 0
): Promise<AnomalyHistoryResponse> {
  const response = await apiFetch(
    `${API_BASE}/api/v1/network/anomalies?limit=${limit}&offset=${offset}`
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}

// Run ML anomaly detection
export async function detectNetworkAnomalies(): Promise<AnomalyDetectionResponse> {
  const response = await apiFetch(
    `${API_BASE}/api/v1/network/detect-anomalies`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  return response.json();
}