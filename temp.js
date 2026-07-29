    /**
     * GLOBAL SCOPE: Ensure resizeIframe is defined before iframe.onload fires.
     */
    window.syncHeights = function() {
        if (window.innerWidth >= 1280) { // xl breakpoint
            const rightPanel = document.getElementById('intelligence-panel');
            const leftCard = document.getElementById('email-content-card');
            if (rightPanel && leftCard) {
                leftCard.style.height = rightPanel.offsetHeight + 'px';
            }
        } else {
            const leftCard = document.getElementById('email-content-card');
            if (leftCard) leftCard.style.height = 'auto';
        }
    };
    window.addEventListener('resize', window.syncHeights);
    document.addEventListener('DOMContentLoaded', () => { setTimeout(window.syncHeights, 100); });

    window.resizeIframe = function(iframe) {
        try {
            iframe.style.height = iframe.contentWindow.document.body.scrollHeight + 'px';
            if (window.syncHeights) window.syncHeights();
        } catch (e) {
            console.warn('SecureMail: Iframe resize calculation suppressed.', e);
        }
    };

    document.addEventListener('DOMContentLoaded', function() {
        // --- 1. Email Body Initialization ---
        const container = document.getElementById('email-body-container');
        const frame = document.getElementById('email-frame');
        
        if (container && frame) {
            let html = container.dataset.html || '';
            
            // Fix missing <style> tags
            if (html.trim().startsWith('@media') || html.trim().startsWith('body {') || html.trim().startsWith('.mercado')) {
                 if (!html.toLowerCase().includes('<style')) {
                     html = '<style>' + html + '</style>' + html;
                 }
            }
            
            // Wrap in Standard Mode boilerplate
            const final_render = html ? `<!DOCTYPE html><html><head><meta charset="utf-8"><base target="_blank"></head><body style="margin:0;padding:0;">${html}</body></html>` : (container.dataset.plain || '');
            
            // SINGLE RENDER SOURCE
            frame.srcdoc = final_render;
        }

        // --- 2. Defensive Intelligence Pipeline ---
        try {
            const analysisElement = document.getElementById('analysis-data');
            const analysis = JSON.parse(analysisElement ? analysisElement.textContent : '{}');
            console.log("PARSED ANALYSIS:", analysis);

            const score = analysis?.score ?? 0;
            const label = analysis?.label ?? "UNKNOWN";
            const confidence = analysis?.confidence ?? 0;

            console.info(`SecureMail: Intelligence initialized. Verdict: ${label} (${score}%)`);
            
            // Hide loader...
            const loader = document.getElementById('analysis-loader');
            if (loader) loader.style.display = 'none';

        } catch (e) {
            console.error("SecureMail: Intelligence parsing failed.", e);
        }

        // --- 3. PDF Export Logic ---
        const pdfBtn = document.getElementById('export-pdf-btn');
        if (pdfBtn) {
            pdfBtn.addEventListener('click', function() {
                const btn = this;
                const originalText = btn.innerText;
                btn.innerText = "GENERATING...";
                btn.disabled = true;

                // Create a temporary container
                const reportContainer = document.createElement('div');
                reportContainer.style.padding = '40px';
                reportContainer.style.fontFamily = 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
                reportContainer.style.color = '#1f2937';
                reportContainer.style.backgroundColor = '#ffffff';
                reportContainer.style.width = '800px';

                // Email Metadata
                const subject = document.querySelector('h1')?.innerText || 'No Subject';
                const senderEl = document.querySelector('h2.text-xl.font-black');
                const sender = senderEl ? senderEl.innerText : 'Unknown Sender';
                const emailAddressEl = document.querySelector('span.text-blue-600.font-mono');
                const emailAddress = emailAddressEl ? emailAddressEl.innerText : '';
                const dateEl = Array.from(document.querySelectorAll('p')).find(p => p.textContent.toLowerCase().includes('sent on'));
                const date = dateEl ? dateEl.textContent.trim().replace(/sent on/i, '').trim() : '';
                
                // Fetch Intelligence Data
                const analysisElement = document.getElementById('analysis-data');
                const analysis = JSON.parse(analysisElement ? analysisElement.textContent : '{}');
                const forensicElement = document.getElementById('forensic-data');
                const forensic = JSON.parse(forensicElement ? forensicElement.textContent : '{}');
                const features = forensic.features || {};
                
                // Original Email Plain Text (Forensic safe)
                const containerEl = document.getElementById('email-body-container');
                let plainText = containerEl?.dataset?.plain || '';
                if (!plainText) {
                    const frame = document.getElementById('email-frame');
                    if (frame && frame.contentDocument) {
                        plainText = frame.contentDocument.body.innerText;
                    }
                }

                // Build Audit Report HTML cleanly
                const riskList = (analysis.risk_factors || []).map(f => `<li style="margin-bottom: 8px; color: #dc2626;">⚠ ${f}</li>`).join('') || '<li style="color: #16a34a;">✔ No manipulative behavioral signals detected.</li>';
                const safeList = (analysis.safe_factors || []).map(f => `<li style="margin-bottom: 8px; color: #16a34a;">✔ ${f}</li>`).join('');
                
                // URL Forensics
                const linkNodes = Array.from(document.querySelectorAll('.border-t.pt-4 .flex.items-center, .border-t.border-gray-300.pt-4 .flex.items-center, .border-t.border-gray-800.pt-4 .flex.items-center'));
                let linksHtml = '';
                if (linkNodes.length > 0) {
                    linksHtml = linkNodes.map(el => {
                        const url = el.querySelector('span.truncate')?.innerText || '';
                        const status = el.querySelectorAll('span')[1]?.innerText || '';
                        const color = status.includes('SAFE') ? '#16a34a' : '#dc2626';
                        return `<tr><td style="padding: 6px; font-size: 11px; font-family: monospace; border-bottom: 1px solid #e2e8f0; color: #374151; word-break: break-all;">${url}</td><td style="padding: 6px; font-size: 11px; font-family: monospace; border-bottom: 1px solid #e2e8f0; text-align: right; color: ${color};">${status}</td></tr>`;
                    }).join('');
                } else {
                    linksHtml = '<tr><td colspan="2" style="padding: 6px; font-size: 12px; color: #6b7280; font-style: italic; border-bottom: 1px solid #e2e8f0;">No external links found.</td></tr>';
                }

                reportContainer.innerHTML = `
                    <div style="border-bottom: 2px solid #2563eb; padding-bottom: 20px; margin-bottom: 30px;">
                        <h1 style="color: #2563eb; margin: 0 0 10px 0; font-size: 28px; font-weight: 900; text-transform: uppercase; letter-spacing: 0.05em;">SecureMail Forensic Report</h1>
                        <p style="margin: 0; color: #6b7280; font-size: 12px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.1em;">Generated by SecureMail Local Intelligence Engine v2.4</p>
                    </div>
                    
                    <div style="margin-bottom: 30px; background: #f8fafc; padding: 20px; border-radius: 12px; border: 1px solid #e2e8f0;">
                        <h2 style="margin: 0 0 15px 0; font-size: 14px; font-weight: 900; color: #4b5563; text-transform: uppercase; letter-spacing: 0.1em; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px;">Email Metadata</h2>
                        <p style="margin: 8px 0; font-size: 14px;"><strong>Subject:</strong> ${subject}</p>
                        <p style="margin: 8px 0; font-size: 14px;"><strong>Sender:</strong> ${sender} ${emailAddress}</p>
                        <p style="margin: 8px 0; font-size: 14px;"><strong>Date:</strong> ${date}</p>
                    </div>

                    <div style="margin-bottom: 40px;">
                        <h2 style="margin: 0 0 15px 0; font-size: 14px; font-weight: 900; color: #4b5563; text-transform: uppercase; letter-spacing: 0.1em; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px;">Original Email Content (Text Extraction)</h2>
                        <div style="border: 1px solid #e2e8f0; padding: 20px; border-radius: 12px; background: #f8fafc; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; color: #1f2937;">${plainText.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
                    </div>

                    <div style="page-break-before: always;">
                        <h2 style="margin: 0 0 20px 0; font-size: 16px; font-weight: 900; color: #1f2937; text-transform: uppercase; letter-spacing: 0.1em; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;">Technical Audit Summary</h2>
                        
                        <table style="width: 100%; margin-bottom: 30px; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 15px; border: 1px solid #e2e8f0; background: #f8fafc; width: 25%;"><strong>Threat Level:</strong><br><span style="font-size: 18px; color: ${analysis.label === 'PHISHING' ? '#dc2626' : (analysis.label === 'SUSPICIOUS' ? '#d97706' : '#16a34a')}">${analysis.label || 'SAFE'}</span></td>
                                <td style="padding: 15px; border: 1px solid #e2e8f0; background: #f8fafc; width: 25%;"><strong>Risk Score:</strong><br><span style="font-size: 18px;">${analysis.score || 0}/100</span></td>
                                <td style="padding: 15px; border: 1px solid #e2e8f0; background: #f8fafc; width: 25%;"><strong>Confidence:</strong><br><span style="font-size: 18px;">${analysis.confidence || 0}%</span></td>
                                <td style="padding: 15px; border: 1px solid #e2e8f0; background: #f8fafc; width: 25%;"><strong>Status:</strong><br><span style="font-size: 18px; color: #2563eb;">${analysis.status || 'FINALIZED'}</span></td>
                            </tr>
                        </table>

                        <div style="margin-bottom: 30px; page-break-inside: avoid;">
                            <h3 style="font-size: 14px; font-weight: bold; color: #dc2626; margin-bottom: 10px;">RISK FACTORS IDENTIFIED</h3>
                            <ul style="list-style-type: none; padding: 0; font-size: 13px;">
                                ${riskList}
                            </ul>
                        </div>

                        <div style="margin-bottom: 40px; page-break-inside: avoid;">
                            <h3 style="font-size: 14px; font-weight: bold; color: #16a34a; margin-bottom: 10px;">SAFE FACTORS DETECTED</h3>
                            <ul style="list-style-type: none; padding: 0; font-size: 13px;">
                                ${safeList}
                            </ul>
                        </div>
                        
                        <table style="width: 100%; border-collapse: separate; border-spacing: 20px 0; margin-left: -20px; page-break-inside: avoid;">
                            <tr>
                                <td style="width: 50%; vertical-align: top; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; background: #f8fafc; box-sizing: border-box;">
                                    <h3 style="font-size: 12px; font-weight: 900; color: #2563eb; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 15px;">URL Forensics</h3>
                                    <table style="width: 100%; font-size: 12px; font-family: monospace; margin-bottom: 15px;">
                                        <tr><td style="color: #6b7280; padding-bottom: 8px;">CTA Density:</td><td style="font-weight: bold; text-align: right; padding-bottom: 8px;">${analysis.cta_count || 0}</td></tr>
                                        <tr><td style="color: #6b7280; padding-bottom: 8px;">Redirect Density:</td><td style="font-weight: bold; text-align: right; padding-bottom: 8px;">${features.marketing_count || 0}</td></tr>
                                        <tr><td style="color: #6b7280; padding-bottom: 8px;">Obfuscated Links:</td><td style="font-weight: bold; text-align: right; padding-bottom: 8px;">${features.shortened_url_count || 0}</td></tr>
                                        <tr><td style="color: #6b7280; padding-bottom: 8px;">Target Domains:</td><td style="font-weight: bold; text-align: right; padding-bottom: 8px;">${features.domain_count || 1}</td></tr>
                                    </table>
                                    <h4 style="font-size: 10px; font-weight: bold; color: #9ca3af; text-transform: uppercase; margin-bottom: 10px;">Target Audit:</h4>
                                    <table style="width: 100%; border-collapse: collapse; table-layout: fixed;">
                                        ${linksHtml}
                                    </table>
                                </td>
                                
                                <td style="width: 50%; vertical-align: top; box-sizing: border-box;">
                                    <div style="border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; background: #f8fafc; margin-bottom: 20px;">
                                        <h3 style="font-size: 12px; font-weight: 900; color: #2563eb; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 15px;">Sender Reputation</h3>
                                        <p style="font-size: 14px; font-weight: bold; margin-bottom: 5px; word-break: break-all;">${emailAddress}</p>
                                        <p style="font-size: 12px; color: ${analysis.trusted_sender ? '#16a34a' : '#6b7280'}; margin-bottom: 15px;">${analysis.trusted_sender ? '✔ Authenticated Sender' : 'Standard Validation'}</p>
                                        <div style="display: flex; justify-content: space-between; font-size: 12px;">
                                            <span style="color: #6b7280;">Trust Score:</span> <span style="font-weight: bold;">${analysis.sender_reputation || 50}/100</span>
                                        </div>
                                    </div>
                                    
                                    <div style="border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; background: #f8fafc;">
                                        <h3 style="font-size: 12px; font-weight: 900; color: #2563eb; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 15px;">ML Decision Breakdown</h3>
                                        <p style="font-size: 11px; color: #6b7280; margin-bottom: 10px;">Linguistic and structural vectorization results:</p>
                                        <p style="font-size: 12px; font-weight: bold; color: #374151; margin-bottom: 15px; word-break: break-word;">${(analysis.suspicious_phrases || []).join(', ') || 'No Suspicious Phrases Detected'}</p>
                                        <table style="width: 100%; font-size: 12px; font-family: monospace;">
                                            <tr><td style="color: #6b7280; padding-bottom: 8px;">Linguistic Complexity:</td><td style="font-weight: bold; text-align: right; padding-bottom: 8px;">${analysis.complexity_score || 0}</td></tr>
                                            <tr><td style="color: #6b7280;">Structural Entropy:</td><td style="font-weight: bold; text-align: right;">${analysis.entropy_score || 0}</td></tr>
                                        </table>
                                    </div>
                                </td>
                            </tr>
                        </table>
                    </div>
                `;

                const iframe = document.createElement('iframe');
                iframe.style.position = 'fixed';
                iframe.style.right = '0';
                iframe.style.bottom = '0';
                iframe.style.width = '0';
                iframe.style.height = '0';
                iframe.style.border = '0';
                document.body.appendChild(iframe);

                const doc = iframe.contentWindow.document;
                doc.open();
                doc.write('<!DOCTYPE html><html><head><title>SecureMail Forensic Report</title>');
                doc.write('<style>');
                doc.write('@page { size: A4 portrait; margin: 15mm; }');
                doc.write('body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: #1f2937; -webkit-print-color-adjust: exact; print-color-adjust: exact; margin: 0; background: #ffffff; }');
                doc.write('</style>');
                doc.write('</head><body>');
                doc.write(reportContainer.outerHTML);
                doc.write('</body></html>');
                doc.close();

                iframe.contentWindow.focus();
                
                // Allow a brief moment for styles/fonts to render in the iframe before printing
                setTimeout(() => {
                    try {
                        iframe.contentWindow.print();
                    } catch (err) {
                        console.error("PDF generation error:", err);
                    } finally {
                        document.body.removeChild(iframe);
                        btn.innerText = originalText;
                        btn.disabled = false;
                    }
                }, 250);
            });
        }
    });
    
    // Lazy Loading Gemini Explainability on Button Click
    const hasGemini = {% if forensic.analysis.gemini_explanation %}true{% else %}false{% endif %};
    let geminiFetchStarted = false;
        
        window.openAuditModal = function() {
            document.getElementById('audit-modal').classList.remove('hidden');
            
            if (!hasGemini && !geminiFetchStarted) {
                geminiFetchStarted = true;
                loadGeminiExplanation();
            }
        };

        function loadGeminiExplanation() {
            const url = "{% url 'generate_explanation' email.id %}";
            const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
            
            fetch(url, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': csrftoken,
                    'Content-Type': 'application/json'
                }
            })
            .then(response => {
                if (response.status === 429) {
                    throw new Error('AI explanation temporarily unavailable.');
                }
                if (!response.ok) {
                    throw new Error('Unable to generate AI explanation.');
                }
                return response.json();
            })
            .then(data => {
                if (data.error) {
                    throw new Error(data.error);
                }
                if (data.explanation) {
                    updateGeminiUI(data.explanation);
                } else {
                    throw new Error('AI returned an invalid response.');
                }
            })
            .catch(error => {
                const msg = error.message || 'Connection lost while contacting AI service.';
                const errorHtml = `
                    <div class="bg-gray-50 p-6 rounded-3xl border border-gray-100 text-center">
                        <p class="text-xs font-bold text-red-500 mb-3">${msg}</p>
                        <button onclick="geminiFetchStarted=true; loadGeminiExplanation()" class="px-4 py-2 bg-purple-500 text-white rounded-xl text-xs font-bold shadow-md hover:bg-purple-600 transition-all">Retry</button>
                    </div>
                `;
                document.querySelectorAll('.gemini-dynamic-container').forEach(el => {
                    el.innerHTML = errorHtml;
                });
            });
        }
        
        function updateGeminiUI(exp) {
            // Update Modal Only
            const modalContainer = document.getElementById('gemini-modal-container');
            if (modalContainer) {
                modalContainer.innerHTML = `
                    <div class="space-y-4">
                        <div class="bg-purple-50/50 p-6 rounded-3xl border border-purple-100/50">
                            <p class="text-sm font-bold text-[var(--sys-text)] leading-relaxed">
                                ${exp.user_explanation || 'No explanation available.'}
                            </p>
                        </div>
                        
                        <div class="bg-gray-50 p-6 rounded-3xl border border-gray-100">
                            <p class="text-[9px] font-black text-[var(--sys-text-secondary)] uppercase tracking-widest mb-2">Technical Analysis</p>
                            <p class="text-xs font-bold text-[var(--sys-text)] leading-relaxed">
                                ${exp.technical_analysis || 'N/A'}
                            </p>
                        </div>

                        <div class="bg-blue-50/50 p-6 rounded-3xl border border-blue-100/50">
                            <p class="text-[9px] font-black text-blue-600 uppercase tracking-widest mb-2">Recommended Action</p>
                            <p class="text-xs font-bold text-blue-800 leading-relaxed">
                                ${exp.recommended_action || 'N/A'}
                            </p>
                        </div>
                    </div>
                `;
            }
            
            // Re-initialize lucide icons for newly injected HTML
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }
        }
