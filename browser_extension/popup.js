const API_URL = 'http://localhost:5000/api/analyze';

document.addEventListener('DOMContentLoaded', async () => {
  const elLoading = document.getElementById('loading');
  const elResult  = document.getElementById('result');
  const elError   = document.getElementById('error');
  
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentUrl = tabs[0]?.url;

    if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
      throw new Error('Cannot scan internal browser pages.');
    }

    elLoading.classList.remove('hidden');

    // Call API (disable visual scanner to make popup fast)
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: currentUrl, visual: false })
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Server error: ${res.status}`);
    }

    const data = await res.json();
    elLoading.classList.add('hidden');
    elResult.classList.remove('hidden');

    // Populate UI
    const banner = document.getElementById('verdict-banner');
    const icon   = document.getElementById('verdict-icon');
    const text   = document.getElementById('verdict-text');
    
    text.textContent = data.verdict;
    document.getElementById('score-text').textContent = `${data.risk_score}/100`;
    document.getElementById('confidence-text').textContent = `${data.confidence}%`;
    document.getElementById('ai-summary').textContent = data.ai_explanation.summary;

    if (data.severity === 'CRITICAL' || data.severity === 'HIGH') {
      banner.className = 'verdict-banner danger';
      icon.textContent = '🚨';
    } else if (data.severity === 'MEDIUM') {
      banner.className = 'verdict-banner warn';
      icon.textContent = '⚠️';
    } else {
      banner.className = 'verdict-banner safe';
      icon.textContent = '✅';
    }

    if (data.brand_result && data.brand_result.brand_impersonation) {
      const bw = document.getElementById('brand-warning');
      bw.classList.remove('hidden');
      document.getElementById('brand-target').textContent = data.brand_result.target_brand;
      document.getElementById('brand-sim').textContent = data.brand_result.similarity;
    }

  } catch (err) {
    elLoading.classList.add('hidden');
    elError.classList.remove('hidden');
    document.getElementById('error-text').textContent = err.message || 'Failed to connect to PhishGuard engine.';
  }

  document.getElementById('btn-retry').addEventListener('click', () => {
    window.location.reload();
  });

  document.getElementById('btn-full-report').addEventListener('click', () => {
    // Open localhost frontend in new tab
    chrome.tabs.create({ url: 'http://localhost:5173' });
  });
});
