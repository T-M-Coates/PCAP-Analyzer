(function () {
  'use strict';

  const dropZone           = document.getElementById('drop-zone');
  const fileInput          = document.getElementById('file-input');
  const analyzeBtn         = document.getElementById('analyze-btn');
  const dropIdle           = document.getElementById('drop-idle');
  const dropSelected       = document.getElementById('drop-selected');
  const fileNameDisplay    = document.getElementById('file-name-display');
  const fileSizeDisplay    = document.getElementById('file-size-display');
  const uploadProgressWrap = document.getElementById('upload-progress-wrap');
  const progressBar        = document.getElementById('progress-bar');
  const progressPct        = document.getElementById('progress-pct');
  const progressLabel      = document.getElementById('progress-label');
  const statusWrap         = document.getElementById('status-wrap');
  const statusMsg          = document.getElementById('status-message');
  const errorWrap          = document.getElementById('error-wrap');
  const errorMsg           = document.getElementById('error-message');

  let selectedFile = null;
  let pollTimer    = null;

  function formatBytes(bytes) {
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
  }

  function showFile(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext !== 'pcap' && ext !== 'pcapng') {
      showError('Only .pcap and .pcapng files are supported.');
      return;
    }
    selectedFile = file;
    fileNameDisplay.textContent = file.name;
    fileSizeDisplay.textContent = formatBytes(file.size);
    dropIdle.classList.add('d-none');
    dropSelected.classList.remove('d-none');
    analyzeBtn.disabled = false;
  }

  function showError(msg) {
    errorMsg.textContent = msg;
    errorWrap.classList.remove('d-none');
    statusWrap.classList.add('d-none');
    uploadProgressWrap.classList.add('d-none');
    analyzeBtn.disabled = false;
  }

  function resetError() {
    errorWrap.classList.add('d-none');
  }

  // --- Drag & drop ---
  dropZone.addEventListener('dragover', function (e) {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', function () {
    dropZone.classList.remove('drag-over');
  });

  dropZone.addEventListener('drop', function (e) {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) showFile(file);
  });

  dropZone.addEventListener('click', function (e) {
    if (e.target.tagName !== 'BUTTON') fileInput.click();
  });

  fileInput.addEventListener('change', function () {
    if (fileInput.files[0]) showFile(fileInput.files[0]);
  });

  // --- Upload (two-phase streaming) ---
  analyzeBtn.addEventListener('click', async function () {
    if (!selectedFile) return;
    resetError();
    analyzeBtn.disabled = true;

    // Phase 1: register the upload, get a job_id back immediately
    let jobId;
    try {
      const r    = await fetch('/upload/init', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ filename: selectedFile.name }),
      });
      const body = await r.json();
      if (!r.ok) { showError(body.error || 'Failed to start upload.'); return; }
      jobId = body.job_id;
    } catch (_) {
      showError('Network error — could not reach the server.');
      return;
    }

    // Phase 2: stream the raw file body; XHR.upload.onprogress drives the bar
    progressLabel.textContent = 'Uploading…';
    progressBar.style.width   = '0%';
    progressPct.textContent   = '0%';
    uploadProgressWrap.classList.remove('d-none');

    const uploadOk = await new Promise(function (resolve) {
      const xhr = new XMLHttpRequest();

      xhr.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          progressBar.style.width = pct + '%';
          progressPct.textContent = pct + '%';
        }
      });

      xhr.addEventListener('load', function () {
        uploadProgressWrap.classList.add('d-none');
        if (xhr.status === 200) {
          resolve(true);
        } else {
          try {
            showError(JSON.parse(xhr.responseText).error || 'Upload failed (HTTP ' + xhr.status + ')');
          } catch (_) {
            showError('Upload failed (HTTP ' + xhr.status + ')');
          }
          resolve(false);
        }
      });

      xhr.addEventListener('error', function () {
        uploadProgressWrap.classList.add('d-none');
        showError('Network error during upload.');
        resolve(false);
      });

      xhr.open('POST', '/upload/' + jobId);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.send(selectedFile);
    });

    if (!uploadOk) return;

    // Phase 3: upload done — poll for analysis progress
    statusWrap.classList.remove('d-none');
    pollStatus(jobId);
  });

  // --- Status polling ---
  function pollStatus(jobId) {
    pollTimer = setInterval(function () {
      fetch('/status/' + jobId)
        .then(function (r) { return r.json(); })
        .then(function (data) {
          const label = data.status_label || 'Analysing…';
          statusMsg.textContent = label + ' ' + data.progress + '%';

          if (data.status === 'complete') {
            clearInterval(pollTimer);
            statusMsg.textContent = 'Analysis complete — loading report…';
            window.location.href  = '/report/' + jobId;
          } else if (data.status === 'error') {
            clearInterval(pollTimer);
            statusWrap.classList.add('d-none');
            showError('Analysis failed. Check the server console for details.');
          }
        })
        .catch(function () {
          clearInterval(pollTimer);
          showError('Lost contact with the server while polling for status.');
        });
    }, 2000);
  }
})();
