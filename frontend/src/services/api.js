const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || 'http://localhost:8000';

/**
 * Check backend health status (GET /api/health)
 */
export async function checkBackendHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/health`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      return { status: 'error', message: `HTTP Error ${response.status}` };
    }

    const data = await response.json();
    return { status: 'ok', data };
  } catch (error) {
    return { status: 'offline', message: error.message || 'Backend server unreachable' };
  }
}

/**
 * Submit Python source code for static security analysis (POST /api/analyze)
 */
export async function analyzeCode(code, filename = 'input.py') {
  if (!code || !code.trim()) {
    return { success: false, error: 'Source code cannot be empty.' };
  }

  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code,
        filename: filename || 'input.py',
      }),
    });

    if (!response.ok) {
      let errorMessage = `Analysis failed with HTTP status ${response.status}`;
      try {
        const errorData = await response.json();
        if (errorData.detail) {
          errorMessage = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
        }
      } catch (e) {
        // Fallback
      }
      return { success: false, error: errorMessage };
    }

    const data = await response.json();
    return { success: true, data };
  } catch (error) {
    return {
      success: false,
      error: error.message || 'Unable to connect to SecureCode Sentinel API. Please ensure backend server is running.',
    };
  }
}

/**
 * Generate a security review report from an AnalysisResult (POST /api/reports)
 */
export async function createReport(analysisResult) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/reports`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ analysis: analysisResult }),
    });

    if (!response.ok) {
      let errorMessage = `Report generation failed with status ${response.status}`;
      try {
        const errObj = await response.json();
        if (errObj.detail) errorMessage = errObj.detail;
      } catch (e) {}
      return { success: false, error: errorMessage };
    }

    const data = await response.json();
    return { success: true, data };
  } catch (error) {
    return {
      success: false,
      error: error.message || 'Failed to generate security review report.',
    };
  }
}

/**
 * Retrieve all stored security reports (GET /api/reports)
 */
export async function getReports() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/reports`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      return { success: false, error: `Failed to fetch reports (${response.status})` };
    }

    const data = await response.json();
    return { success: true, data };
  } catch (error) {
    return { success: false, error: error.message || 'Failed to connect to reports API.' };
  }
}

/**
 * Retrieve a specific security report by ID (GET /api/reports/{report_id})
 */
export async function getReport(reportId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/reports/${encodeURIComponent(reportId)}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (response.status === 404) {
      return { success: false, error: `Security report '${reportId}' not found.`, notFound: true };
    }

    if (!response.ok) {
      return { success: false, error: `Failed to fetch report ${reportId}` };
    }

    const data = await response.json();
    return { success: true, data };
  } catch (error) {
    return { success: false, error: error.message || 'Failed to connect to report API.' };
  }
}
