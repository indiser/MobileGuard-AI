export const API_BASE = 'http://localhost:8000';

export async function uploadAPK(file, onEvent) {
  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      let errStr = "Analysis failed";
      try {
        const errorData = await response.json();
        errStr = errorData.detail || errStr;
      } catch (e) {}
      throw new Error(errStr);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.substring(6));
            onEvent(data);
          } catch (e) {
            console.error("Failed to parse SSE line", line);
          }
        }
      }
    }
  } catch (err) {
    onEvent({ stage: 'error', status: 'failed', error: err.message });
  }
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}
