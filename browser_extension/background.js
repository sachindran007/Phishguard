chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan_phishguard",
    title: "Scan link with PhishGuard",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan_phishguard") {
    const linkUrl = info.linkUrl;
    
    // Inject a loading toast into the active tab
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (url) => {
        const toast = document.createElement('div');
        toast.id = 'pg-toast';
        toast.style.cssText = `
          position: fixed; top: 20px; right: 20px; z-index: 999999;
          background: #080f1f; color: #fff; padding: 16px 24px;
          border-radius: 8px; border: 1px solid #3b82f6;
          font-family: sans-serif; box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        `;
        toast.innerHTML = `Scanning <strong>${url.substring(0,30)}...</strong> with PhishGuard`;
        document.body.appendChild(toast);
      },
      args: [linkUrl]
    });

    // Call API
    fetch('http://localhost:5000/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: linkUrl, visual: false })
    })
    .then(r => r.json())
    .then(data => {
      // Update toast
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (data) => {
          const t = document.getElementById('pg-toast');
          if (t) {
            const isDanger = data.risk_score > 60;
            t.style.borderColor = isDanger ? '#ef4444' : '#22c55e';
            t.innerHTML = `
              <div style="font-size:16px;font-weight:bold;color:${isDanger?'#ef4444':'#22c55e'}">
                ${data.verdict} (Score: ${data.risk_score})
              </div>
              <div style="font-size:12px;margin-top:4px;color:#cbd5e1">
                ${data.ai_explanation?.summary?.substring(0,60)}...
              </div>
            `;
            setTimeout(() => t.remove(), 5000);
          }
        },
        args: [data]
      });
    })
    .catch(err => {
       chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const t = document.getElementById('pg-toast');
          if (t) {
            t.style.borderColor = '#ef4444';
            t.innerHTML = `PhishGuard Error: Could not connect to local engine.`;
            setTimeout(() => t.remove(), 4000);
          }
        }
      });
    });
  }
});
