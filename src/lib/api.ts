export const apiFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const getCookie = (name: string) => {
    if (typeof document === 'undefined') return '';
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift();
    return '';
  };

  const token = getCookie('XSRF-TOKEN');
  
  const config = { ...(init || {}) };
  const headers = new Headers(config.headers || {});
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json, text/plain, */*');
  }

  if (config.method && !['GET', 'HEAD', 'OPTIONS'].includes(config.method.toUpperCase())) {
    if (token) {
      headers.set('X-XSRF-TOKEN', token);
    }
  }
  config.headers = headers;
  
  const response = await fetch(input, config);

  // Safe wrapper around json() to prevent JSON parsing crashes if HTML/plain text is returned
  const originalJson = response.json.bind(response);
  response.json = async () => {
    const clone = response.clone();
    try {
      return await originalJson();
    } catch {
      const text = await clone.text();
      return {
        error: response.ok ? 'Invalid JSON response' : `HTTP Error ${response.status}`,
        message: text.startsWith('<!') ? `Server returned HTML status ${response.status}` : text,
        status: response.status
      };
    }
  };

  return response;
};