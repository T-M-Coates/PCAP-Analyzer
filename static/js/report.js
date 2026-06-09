'use strict';

// ── Charts ─────────────────────────────────────────────────────
function initCharts() {
  var d = window.CHART_DATA;
  if (!d) return;

  var pieCtx = document.getElementById('protoPieChart');
  if (pieCtx) {
    new Chart(pieCtx, {
      type: 'doughnut',
      data: {
        labels: d.proto.labels,
        datasets: [{
          data: d.proto.values,
          backgroundColor: ['#0d6efd', '#fd7e14', '#6c757d'],
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { position: 'bottom' },
          tooltip: {
            callbacks: {
              label: function(ctx) {
                var total = ctx.dataset.data.reduce(function(a, b) { return a + b; }, 0);
                var pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                return ctx.label + ': ' + ctx.parsed.toLocaleString() + ' (' + pct + '%)';
              }
            }
          }
        }
      }
    });
  }

  var barCtx = document.getElementById('topSendersBar');
  if (barCtx && d.topSenders && d.topSenders.length) {
    var labels = d.topSenders.map(function(h) { return h.ip; });
    var values = d.topSenders.map(function(h) { return h.packets_sent; });
    new Chart(barCtx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Packets sent',
          data: values,
          backgroundColor: '#0d6efd',
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function(ctx) {
                return ctx.parsed.x.toLocaleString() + ' packets';
              }
            }
          }
        },
        scales: {
          x: { beginAtZero: true, ticks: { callback: function(v) { return v.toLocaleString(); } } }
        }
      }
    });
  }
}

// ── Sortable tables ─────────────────────────────────────────────
function initSortableTables() {
  document.querySelectorAll('.sortable-table').forEach(function(table) {
    table.querySelectorAll('th.sortable').forEach(function(th) {
      th.style.cursor = 'pointer';
      th.title = 'Click to sort';
      th.dataset.sortDir = 'none';

      th.addEventListener('click', function() {
        var tbody    = table.querySelector('tbody');
        var rows     = Array.from(tbody.querySelectorAll('tr'));
        var colIdx   = Array.from(th.parentElement.children).indexOf(th);
        var asc      = th.dataset.sortDir !== 'asc';
        var isNum    = th.dataset.type === 'num';

        rows.sort(function(a, b) {
          var aTxt = a.children[colIdx] ? a.children[colIdx].textContent.trim() : '';
          var bTxt = b.children[colIdx] ? b.children[colIdx].textContent.trim() : '';
          if (isNum) {
            var aVal = parseFloat(aTxt.replace(/[^0-9.-]/g, '')) || 0;
            var bVal = parseFloat(bTxt.replace(/[^0-9.-]/g, '')) || 0;
            return asc ? aVal - bVal : bVal - aVal;
          }
          return asc ? aTxt.localeCompare(bTxt) : bTxt.localeCompare(aTxt);
        });

        rows.forEach(function(row) { tbody.appendChild(row); });

        // Reset indicators on sibling headers
        th.closest('tr').querySelectorAll('th').forEach(function(t) {
          t.dataset.sortDir = 'none';
          t.textContent = t.textContent.replace(/\s[↑↓]$/, '');
        });
        th.dataset.sortDir = asc ? 'asc' : 'desc';
        th.textContent += asc ? ' ↑' : ' ↓';
      });
    });
  });
}

// ── Expandable HTTP detail rows ─────────────────────────────────
function initExpandableRows() {
  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.http-toggle');
    if (!btn) return;
    var idx    = btn.dataset.idx;
    var detail = document.getElementById('http-detail-' + idx);
    if (!detail) return;
    var opening = detail.classList.contains('d-none');
    detail.classList.toggle('d-none', !opening);
    btn.textContent = opening ? '▲' : '▼';
  });
}

// ── Copy all IOCs to clipboard ──────────────────────────────────
function initCopyIOCs() {
  var btn = document.getElementById('copyIocsBtn');
  if (!btn) return;

  btn.addEventListener('click', function() {
    var rows = document.querySelectorAll('#iocTable tbody tr');
    var lines = Array.from(rows).map(function(row) {
      var cells = row.querySelectorAll('td');
      var sev   = cells[0] ? cells[0].textContent.trim() : '';
      var type  = cells[1] ? cells[1].textContent.trim() : '';
      var value = cells[2] ? cells[2].textContent.trim() : '';
      var desc  = cells[3] ? cells[3].textContent.trim() : '';
      return '[' + sev + '] ' + type + ': ' + value + ' — ' + desc;
    });

    navigator.clipboard.writeText(lines.join('\n')).then(function() {
      btn.textContent = '✓ Copied!';
      btn.classList.replace('btn-outline-secondary', 'btn-success');
      setTimeout(function() {
        btn.textContent = 'Copy all IOCs';
        btn.classList.replace('btn-success', 'btn-outline-secondary');
      }, 2500);
    }).catch(function() {
      alert('Clipboard not available — please copy manually.');
    });
  });
}

// ── Export IOC table as CSV ─────────────────────────────────────
function initExportCSV() {
  var btn = document.getElementById('exportCsvBtn');
  if (!btn) return;

  btn.addEventListener('click', function() {
    var rows = document.querySelectorAll('#iocTable tbody tr');
    var csvLines = ['severity,type,value,description,source_module'];

    rows.forEach(function(row) {
      var cells = Array.from(row.querySelectorAll('td')).map(function(td) {
        return '"' + td.textContent.trim().replace(/"/g, '""') + '"';
      });
      csvLines.push(cells.join(','));
    });

    var blob = new Blob([csvLines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    a.href     = url;
    a.download = 'iocs.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });
}

// ── Packet volume over time ─────────────────────────────────────
function initPacketTimeline() {
  var ctx = document.getElementById('packetTimelineChart');
  var body = document.getElementById('packetTimelineBody');
  if (!ctx || !body) return;

  var d = window.CHART_DATA;
  if (!d || !d.timeline || !d.timeline.labels || d.timeline.labels.length === 0) {
    body.innerHTML = '<p class="text-muted text-center py-3 mb-0">No timeline data available — re-analyse to generate this chart.</p>';
    return;
  }

  var isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
  var gridColor = isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
  var tickColor = isDark ? '#adb5bd' : '#6c757d';

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: d.timeline.labels,
      datasets: [{
        label: 'Packets',
        data: d.timeline.values,
        backgroundColor: 'rgba(13, 110, 253, 0.55)',
        borderColor: 'rgba(13, 110, 253, 0.85)',
        borderWidth: 1,
        borderRadius: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: function(ctx) {
              return ctx.parsed.y.toLocaleString() + ' packets';
            }
          }
        }
      },
      scales: {
        x: {
          ticks: { color: tickColor, maxTicksLimit: 24, maxRotation: 45 },
          grid: { color: gridColor }
        },
        y: {
          beginAtZero: true,
          ticks: {
            color: tickColor,
            callback: function(v) { return v.toLocaleString(); }
          },
          grid: { color: gridColor }
        }
      }
    }
  });
}

// ── ISO 3166-1 numeric → alpha-2 lookup (for GeoIP world map) ───
var _NUM_TO_A2 = {
  "004":"AF","008":"AL","012":"DZ","016":"AS","020":"AD","024":"AO",
  "028":"AG","031":"AZ","032":"AR","036":"AU","040":"AT","044":"BS",
  "048":"BH","050":"BD","051":"AM","056":"BE","060":"BM","064":"BT",
  "068":"BO","070":"BA","072":"BW","076":"BR","084":"BZ","096":"BN",
  "100":"BG","104":"MM","108":"BI","112":"BY","116":"KH","120":"CM",
  "124":"CA","132":"CV","136":"KY","140":"CF","144":"LK","148":"TD",
  "152":"CL","156":"CN","170":"CO","174":"KM","178":"CG","180":"CD",
  "184":"CK","188":"CR","191":"HR","192":"CU","196":"CY","203":"CZ",
  "204":"BJ","208":"DK","212":"DM","214":"DO","218":"EC","222":"SV",
  "226":"GQ","231":"ET","232":"ER","233":"EE","238":"FK","242":"FJ",
  "246":"FI","250":"FR","258":"PF","262":"DJ","266":"GA","268":"GE",
  "270":"GM","275":"PS","276":"DE","288":"GH","292":"GI","296":"KI",
  "300":"GR","308":"GD","320":"GT","324":"GN","328":"GY","332":"HT",
  "336":"VA","340":"HN","344":"HK","348":"HU","356":"IN","360":"ID",
  "364":"IR","368":"IQ","372":"IE","376":"IL","380":"IT","384":"CI",
  "388":"JM","392":"JP","398":"KZ","400":"JO","404":"KE","408":"KP",
  "410":"KR","414":"KW","417":"KG","418":"LA","422":"LB","426":"LS",
  "428":"LV","430":"LR","434":"LY","440":"LT","442":"LU","446":"MO",
  "450":"MG","454":"MW","458":"MY","462":"MV","466":"ML","470":"MT",
  "478":"MR","480":"MU","484":"MX","492":"MC","496":"MN","498":"MD",
  "499":"ME","504":"MA","508":"MZ","516":"NA","520":"NR","524":"NP",
  "528":"NL","540":"NC","548":"VU","554":"NZ","558":"NI","562":"NE",
  "566":"NG","578":"NO","583":"FM","584":"MH","585":"PW","586":"PK",
  "591":"PA","598":"PG","604":"PE","608":"PH","616":"PL","620":"PT",
  "626":"TL","630":"PR","634":"QA","638":"RE","642":"RO","643":"RU",
  "646":"RW","659":"KN","662":"LC","670":"VC","678":"ST","682":"SA",
  "686":"SN","688":"RS","690":"SC","694":"SL","703":"SK","706":"SO",
  "710":"ZA","716":"ZW","724":"ES","728":"SS","729":"SD","740":"SR",
  "748":"SZ","752":"SE","756":"CH","760":"SY","762":"TJ","764":"TH",
  "768":"TG","776":"TO","780":"TT","784":"AE","788":"TN","792":"TR",
  "795":"TM","800":"UG","804":"UA","807":"MK","818":"EG","826":"GB",
  "834":"TZ","840":"US","850":"VI","858":"UY","860":"UZ","862":"VE",
  "882":"WS","887":"YE","894":"ZM"
};

// ── GeoIP world map (choropleth via chartjs-chart-geo) ──────────
function initGeoMap() {
  var body = document.getElementById('geoMapBody');
  var ctx  = document.getElementById('geoMapChart');
  if (!ctx || !body) return;

  var d = window.CHART_DATA;
  var geoData = (d && d.geomap) ? d.geomap : {};

  if (Object.keys(geoData).length === 0) {
    body.innerHTML =
      '<p class="text-muted text-center py-4 mb-0">' +
      'No geographic data available.<br>' +
      '<small>Add a <code>GeoLite2-Country.mmdb</code> file to enable the world map.</small>' +
      '</p>';
    return;
  }

  var maxVal = Math.max.apply(null, Object.values(geoData).concat([1]));

  fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
    .then(function(r) { return r.json(); })
    .then(function(world) {
      var ChartGeo = window.ChartGeo;
      if (!ChartGeo) { throw new Error('chartjs-chart-geo not loaded'); }

      var features = ChartGeo.topojson.feature(world, world.objects.countries).features;
      var isDark   = document.documentElement.getAttribute('data-bs-theme') === 'dark';

      var emptyFill   = isDark ? 'rgba(255,255,255,0.07)' : 'rgba(200,200,200,0.35)';
      var emptyBorder = isDark ? 'rgba(255,255,255,0.12)' : 'rgba(150,150,150,0.4)';

      // Build country name lookup from features for tooltip
      var numToName = {};
      features.forEach(function(f) {
        if (f.properties && f.properties.name) {
          numToName[String(f.id)] = f.properties.name;
        }
      });

      new Chart(ctx, {
        type: 'choropleth',
        data: {
          labels: features.map(function(f) {
            return numToName[String(f.id)] || '';
          }),
          datasets: [{
            data: features.map(function(f) {
              var numKey = ('00' + f.id).slice(-3);
              var a2 = _NUM_TO_A2[numKey] || '';
              return { feature: f, value: geoData[a2] || 0 };
            }),
            backgroundColor: function(context) {
              if (!context.dataset || !context.dataset.data) return emptyFill;
              var item = context.dataset.data[context.dataIndex];
              if (!item || item.value === 0) return emptyFill;
              var t = item.value / maxVal;
              // Gradient: light amber (#ffc107 at t=0.1) → deep red (#dc3545 at t=1)
              var r = Math.round(220 + (220 - 220) * t);   // stays ~220
              var g = Math.round(193 - 193 * t);            // 193 → 0
              var b = Math.round(7   + (53  - 7)  * t);    // 7 → 53
              var a = 0.35 + t * 0.65;
              return 'rgba(' + r + ',' + g + ',' + b + ',' + a.toFixed(2) + ')';
            },
            borderColor: function(context) {
              if (!context.dataset || !context.dataset.data) return emptyBorder;
              var item = context.dataset.data[context.dataIndex];
              return (!item || item.value === 0) ? emptyBorder : 'rgba(180,40,40,0.5)';
            },
            borderWidth: 0.5
          }]
        },
        options: {
          showOutline: true,
          showGraticule: false,
          responsive: true,
          maintainAspectRatio: true,
          aspectRatio: 2,
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                title: function() { return ''; },
                label: function(context) {
                  var item = context.dataset.data[context.dataIndex];
                  var name = context.chart.data.labels[context.dataIndex] || 'Unknown';
                  if (!item || item.value === 0) return name;
                  return name + ': ' + item.value + ' host' + (item.value !== 1 ? 's' : '');
                }
              }
            }
          },
          scales: {
            projection: {
              axis: 'x',
              projection: 'equalEarth'
            }
          }
        }
      });
    })
    .catch(function() {
      body.innerHTML =
        '<p class="text-muted text-center py-4 mb-0">' +
        'World map could not be loaded — requires an internet connection on first use.' +
        '</p>';
    });
}

// ── Timeline toggle (Suspicious ↔ All) ─────────────────────────
function initTimeline() {
  var btnSusp = document.getElementById('tlBtnSuspicious');
  var btnAll  = document.getElementById('tlBtnAll');
  var empty   = document.getElementById('tlEmpty');
  if (!btnSusp || !btnAll) return;

  function _applyFilter(showAll) {
    var items   = document.querySelectorAll('.timeline-item');
    var visible = 0;
    items.forEach(function(item) {
      var susp = item.dataset.suspicious === 'true';
      var show = showAll || susp;
      item.classList.toggle('d-none', !show);
      if (show) visible++;
    });
    if (empty) empty.classList.toggle('d-none', visible > 0);

    btnSusp.classList.toggle('btn-primary',   !showAll);
    btnSusp.classList.toggle('btn-outline-secondary', showAll);
    btnAll.classList.toggle('btn-primary',    showAll);
    btnAll.classList.toggle('btn-outline-secondary',  !showAll);
  }

  // Default: show suspicious only
  _applyFilter(false);

  btnSusp.addEventListener('click', function() { _applyFilter(false); });
  btnAll.addEventListener('click',  function() { _applyFilter(true);  });
}

// ── Dark mode toggle ────────────────────────────────────────────
function initDarkMode() {
  var btn = document.getElementById('darkModeBtn');
  if (!btn) return;

  function _apply(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    btn.textContent = theme === 'dark' ? '☀' : '🌙';
    btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
  }

  // Set initial icon to match current theme (applied before paint by inline script)
  var current = document.documentElement.getAttribute('data-bs-theme') || 'light';
  _apply(current);

  btn.addEventListener('click', function() {
    var next = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
    _apply(next);
    try { localStorage.setItem('pcap-theme', next); } catch(e) {}
  });
}

// ── History tab (lazy-loaded from /history) ──────────────────────
function initHistoryTab() {
  var tabBtn = document.querySelector('[data-bs-target="#tab-history"]');
  if (!tabBtn) return;

  var loaded = false;

  tabBtn.addEventListener('shown.bs.tab', function() {
    if (loaded) return;
    loaded = true;

    fetch('/history')
      .then(function(r) { return r.json(); })
      .then(function(analyses) {
        var loading = document.getElementById('historyLoading');
        var content = document.getElementById('historyContent');
        var empty   = document.getElementById('historyEmpty');
        var tbody   = document.getElementById('historyTableBody');

        if (loading) loading.classList.add('d-none');

        if (!analyses || analyses.length === 0) {
          if (empty) empty.classList.remove('d-none');
          return;
        }

        analyses.forEach(function(a) {
          var tr = document.createElement('tr');
          var completed = a.completed_at ? a.completed_at.replace('T', ' ').substring(0, 16) : '—';
          tr.innerHTML =
            '<td class="font-monospace small">' + _esc(a.filename) + '</td>' +
            '<td class="small text-muted text-nowrap">' + _esc(completed) + '</td>' +
            '<td class="text-center"><span class="badge bg-danger">' + (a.critical_count || 0) + '</span></td>' +
            '<td class="text-center"><span class="badge bg-high">' + (a.high_count || 0) + '</span></td>' +
            '<td class="text-center"><span class="badge bg-warning text-dark">' + (a.medium_count || 0) + '</span></td>' +
            '<td class="text-center"><span class="badge bg-info text-dark">' + (a.info_count || 0) + '</span></td>' +
            '<td class="text-end text-nowrap">' +
              '<a href="/report/' + _esc(a.job_id) + '" class="btn btn-sm btn-outline-primary me-1">View</a>' +
              '<button class="btn btn-sm btn-outline-danger" data-job="' + _esc(a.job_id) + '">Delete</button>' +
            '</td>';
          tbody.appendChild(tr);
        });

        if (content) content.classList.remove('d-none');

        // Delete buttons
        tbody.addEventListener('click', function(e) {
          var btn = e.target.closest('[data-job]');
          if (!btn) return;
          var jobId = btn.dataset.job;
          if (!confirm('Delete this analysis record and its files?')) return;
          fetch('/analysis/' + jobId, { method: 'DELETE' })
            .then(function() {
              var row = btn.closest('tr');
              if (row) row.remove();
              if (!tbody.querySelector('tr')) {
                if (content) content.classList.add('d-none');
                if (empty)   empty.classList.remove('d-none');
              }
            })
            .catch(function() { alert('Delete failed.'); });
        });
      })
      .catch(function() {
        var loading = document.getElementById('historyLoading');
        if (loading) loading.textContent = 'Failed to load history.';
      });
  });
}

// Simple HTML escaper for JS-built table content
function _esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── IOC filter bar ──────────────────────────────────────────────
function initIocFilterBar() {
  var rows = document.querySelectorAll('#iocTable tbody tr.ioc-row');
  if (!rows.length) return;

  var activeSev = 'ALL', activeType = '', searchTerm = '';

  function applyIocFilters() {
    rows.forEach(function(row) {
      var show = (activeSev === 'ALL' || (row.dataset.sev || '') === activeSev)
              && (!activeType || (row.dataset.type || '') === activeType)
              && (!searchTerm || (row.dataset.search || '').includes(searchTerm));
      row.classList.toggle('d-none', !show);
    });
  }

  document.querySelectorAll('.ioc-sev-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.ioc-sev-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      activeSev = btn.dataset.sev;
      applyIocFilters();
    });
  });

  var typeSelect = document.getElementById('ioc-type-filter');
  if (typeSelect) {
    typeSelect.addEventListener('change', function() { activeType = this.value; applyIocFilters(); });
  }

  var searchInput = document.getElementById('ioc-search');
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      searchTerm = this.value.trim().toLowerCase();
      applyIocFilters();
    });
  }
}

// ── Hosts filter bar ────────────────────────────────────────────
function initHostsFilterBar() {
  var internalCard = document.getElementById('hosts-internal-card');
  var externalCard = document.getElementById('hosts-external-card');
  if (!internalCard || !externalCard) return;

  document.querySelectorAll('.host-sec-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.host-sec-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      var show = btn.dataset.show;
      internalCard.classList.toggle('d-none', show === 'external');
      externalCard.classList.toggle('d-none', show === 'internal');
    });
  });

  var searchInput = document.getElementById('host-search');
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      var term = this.value.trim().toLowerCase();
      document.querySelectorAll('.host-row').forEach(function(row) {
        var hit = !term
          || (row.dataset.ip   || '').includes(term)
          || (row.dataset.name || '').includes(term);
        row.classList.toggle('d-none', !hit);
      });
    });
  }
}

// ── DNS filter bar ──────────────────────────────────────────────
function initDnsFilter() {
  var searchInput = document.getElementById('dns-search');
  var activeFlag  = 'ALL';
  var allQueriesCard = null;

  // Find the "All DNS queries" card (second card in the DNS tab)
  var dnsTab = document.getElementById('tab-dns');
  if (dnsTab) {
    var cards = dnsTab.querySelectorAll('.card');
    allQueriesCard = cards[cards.length - 1] || null;
  }

  function applyDnsFilters() {
    var term = searchInput ? searchInput.value.trim().toLowerCase() : '';

    // Flagged rows (in the first card, if present)
    document.querySelectorAll('.dns-flagged-row').forEach(function(row) {
      var flags  = row.dataset.flags  || '';
      var search = row.dataset.search || '';
      var hit = (activeFlag === 'ALL' || flags.includes(activeFlag))
             && (!term || search.includes(term));
      row.classList.toggle('d-none', !hit);
    });

    // When a specific flag filter is active, hide the all-queries card
    // (it doesn't have flag data, so showing it would be misleading)
    if (allQueriesCard) {
      allQueriesCard.classList.toggle('d-none', activeFlag !== 'ALL');
    }

    // All-query rows — only affected by search
    if (activeFlag === 'ALL') {
      document.querySelectorAll('.dns-query-row').forEach(function(row) {
        var search = row.dataset.search || '';
        row.classList.toggle('d-none', !!term && !search.includes(term));
      });
    }
  }

  document.querySelectorAll('.dns-flag-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.dns-flag-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      activeFlag = btn.dataset.flag;
      applyDnsFilters();
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', function() { applyDnsFilters(); });
  }
}

// ── HTTP filter bar ─────────────────────────────────────────────
function initHttpFilterBar() {
  var searchInput  = document.getElementById('http-search');
  var activeMethod = 'ALL';

  function applyHttpFilters() {
    var term = searchInput ? searchInput.value.trim().toLowerCase() : '';

    document.querySelectorAll('.http-filterable').forEach(function(row) {
      var method  = row.dataset.method  || '';
      var flagged = row.dataset.flagged === 'true';
      var search  = row.dataset.search  || '';

      var methodHit = activeMethod === 'ALL'
        || (activeMethod === 'FLAGGED' && flagged)
        || method === activeMethod;
      var searchHit = !term || search.includes(term);

      row.classList.toggle('d-none', !(methodHit && searchHit));
    });
  }

  document.querySelectorAll('.http-method-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.http-method-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      activeMethod = btn.dataset.method;
      applyHttpFilters();
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', function() { applyHttpFilters(); });
  }
}

// ── IP Profile Modal ────────────────────────────────────────────
function initIpModal() {
  var modalEl = document.getElementById('ip-profile-modal');
  if (!modalEl || !window.REPORT_DATA) return;

  var bsModal   = new bootstrap.Modal(modalEl);
  var addrEl    = document.getElementById('ip-modal-addr');
  var bodyEl    = document.getElementById('ip-modal-body');

  document.addEventListener('click', function(e) {
    var link = e.target.closest('a.ip-link');
    if (!link) return;
    e.preventDefault();
    var ip = link.dataset.ip;
    if (!ip) return;
    if (addrEl) addrEl.textContent = ip;
    if (bodyEl) bodyEl.innerHTML = _buildIpProfile(ip);
    bsModal.show();
  });
}

function _buildIpProfile(ip) {
  var d = window.REPORT_DATA;
  var sections = [];

  // ── Host details ─────────────────────────────────────────────
  var host = (d.hosts || []).find(function(h) { return h.ip === ip; });
  var resolvedName = (d.domainMap || {})[ip] || null;
  if (host) {
    var typeLabel = host.type || (host.is_internal ? 'Internal' : 'External');
    sections.push(
      '<div class="p-3 border-bottom">' +
      '<h6 class="fw-semibold mb-2 small text-uppercase text-muted">Host Details</h6>' +
      '<div class="row g-2 small">' +
      '<div class="col-6 col-md-3"><div class="text-muted">Type</div><strong>' + _esc(typeLabel) + '</strong></div>' +
      '<div class="col-6 col-md-3"><div class="text-muted">Sent</div><strong>' + (host.packets_sent  || 0).toLocaleString() + ' pkts</strong></div>' +
      '<div class="col-6 col-md-3"><div class="text-muted">Received</div><strong>' + (host.packets_received || 0).toLocaleString() + ' pkts</strong></div>' +
      (resolvedName ? '<div class="col-6 col-md-3"><div class="text-muted">Hostname</div><code>' + _esc(resolvedName) + '</code></div>' : '') +
      (host.country ? '<div class="col-6 col-md-3 mt-1"><div class="text-muted">Country</div><strong>' + _esc(host.country) + '</strong></div>' : '') +
      (host.asn_description ? '<div class="col-6 col-md-3 mt-1"><div class="text-muted">ASN</div><span class="small">' + _esc(host.asn_description) + '</span></div>' : '') +
      '</div></div>'
    );
  } else if (resolvedName) {
    sections.push(
      '<div class="p-3 border-bottom">' +
      '<h6 class="fw-semibold mb-1 small text-uppercase text-muted">Hostname</h6>' +
      '<code>' + _esc(resolvedName) + '</code>' +
      '</div>'
    );
  }

  // ── IOCs ─────────────────────────────────────────────────────
  var iocs = (d.iocs || []).filter(function(i) {
    return i.value === ip || (i.description || '').includes(ip);
  });
  if (iocs.length) {
    var sevCls = { CRITICAL: 'danger', HIGH: 'warning', MEDIUM: 'warning', INFO: 'info' };
    var rows = iocs.map(function(i) {
      var cls = sevCls[i.severity] || 'secondary';
      var txtDark = (i.severity === 'HIGH' || i.severity === 'MEDIUM') ? ' text-dark' : '';
      return '<tr><td><span class="badge bg-' + cls + txtDark + '">' + _esc(i.severity) + '</span></td>' +
             '<td class="small text-muted">' + _esc(i.type) + '</td>' +
             '<td class="font-monospace small">' + _esc(i.value) + '</td>' +
             '<td class="small">' + _esc(i.description) + '</td></tr>';
    }).join('');
    sections.push(
      '<div class="p-3 border-bottom">' +
      '<h6 class="fw-semibold mb-2 small text-uppercase text-muted text-danger">IOCs (' + iocs.length + ')</h6>' +
      '<div class="table-responsive">' +
      '<table class="table table-sm mb-0"><thead class="table-light"><tr><th>Sev</th><th>Type</th><th>Value</th><th>Description</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div></div>'
    );
  }

  // ── DNS ───────────────────────────────────────────────────────
  var dnsFrom = (d.dns || []).filter(function(q) {
    return (q.queried_by || []).includes(ip);
  });
  var dnsTo = (d.dns || []).filter(function(q) {
    return (q.resolved_ips || []).includes(ip);
  });
  if (dnsFrom.length || dnsTo.length) {
    var html = '<div class="p-3 border-bottom">' +
      '<h6 class="fw-semibold mb-2 small text-uppercase text-muted">DNS Activity</h6>';
    if (dnsFrom.length) {
      var rows = dnsFrom.map(function(q) {
        return '<tr><td class="font-monospace small">' + _esc(q.domain) + '</td>' +
               '<td class="text-end">' + (q.query_count || 0) + '</td>' +
               '<td class="small text-muted">' + _esc((q.resolved_ips || []).join(', ') || '—') + '</td></tr>';
      }).join('');
      html += '<p class="small text-muted mb-1">Queries issued by this host (' + dnsFrom.length + '):</p>' +
        '<div class="table-responsive"><table class="table table-sm mb-3">' +
        '<thead class="table-light"><tr><th>Domain</th><th class="text-end">Count</th><th>Resolved IPs</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>';
    }
    if (dnsTo.length) {
      html += '<p class="small text-muted mb-1">Domains that resolve to this IP (' + dnsTo.length + '):</p>' +
        '<ul class="list-unstyled mb-0 small font-monospace ps-1">' +
        dnsTo.map(function(q) { return '<li>' + _esc(q.domain) + '</li>'; }).join('') + '</ul>';
    }
    html += '</div>';
    sections.push(html);
  }

  // ── HTTP ─────────────────────────────────────────────────────
  var httpFrom = (d.http || []).filter(function(r) {
    return (r.src === ip || r.src_ip === ip);
  });
  var httpTo = (d.http || []).filter(function(r) {
    return (r.dst === ip || r.dst_ip === ip);
  });
  if (httpFrom.length || httpTo.length) {
    var html = '<div class="p-3 border-bottom">' +
      '<h6 class="fw-semibold mb-2 small text-uppercase text-muted">HTTP Requests</h6>';
    if (httpFrom.length) {
      var rows = httpFrom.slice(0, 25).map(function(r) {
        var badge = r.method === 'POST'
          ? '<span class="badge bg-warning text-dark">POST</span>'
          : '<span class="badge bg-secondary">' + _esc(r.method) + '</span>';
        return '<tr><td>' + badge + '</td>' +
               '<td class="small">' + _esc(r.host || '') + '</td>' +
               '<td class="font-monospace small text-truncate" style="max-width:260px">' + _esc(r.uri || r.path || '') + '</td></tr>';
      }).join('');
      var extra = httpFrom.length > 25
        ? '<tr><td colspan="3" class="text-center text-muted small">… ' + (httpFrom.length - 25) + ' more</td></tr>'
        : '';
      html += '<p class="small text-muted mb-1">Requests from this host (' + httpFrom.length + '):</p>' +
        '<div class="table-responsive"><table class="table table-sm mb-3">' +
        '<thead class="table-light"><tr><th>Method</th><th>Host</th><th>Path</th></tr></thead>' +
        '<tbody>' + rows + extra + '</tbody></table></div>';
    }
    if (httpTo.length) {
      html += '<p class="small text-muted mb-1">Requests to this IP (' + httpTo.length + '):</p>' +
        '<ul class="list-unstyled mb-0 small font-monospace ps-1">' +
        httpTo.slice(0, 10).map(function(r) {
          return '<li>' + _esc(r.host || ip) + _esc(r.uri || r.path || '') + '</li>';
        }).join('') + '</ul>';
    }
    html += '</div>';
    sections.push(html);
  }

  // ── Beaconing ─────────────────────────────────────────────────
  var beacons = (d.beaconing || []).filter(function(b) {
    return b.src === ip || b.dst === ip;
  });
  if (beacons.length) {
    var rows = beacons.map(function(b) {
      var cvCls = b.cv < 0.05 ? 'cv-high' : (b.cv < 0.20 ? 'cv-medium' : 'cv-low');
      return '<tr><td class="font-monospace small">' + _esc(b.src) + '</td>' +
             '<td class="font-monospace small">' + _esc(b.dst) + '</td>' +
             '<td class="text-end">' + (b.port || '') + '</td>' +
             '<td class="text-end">' + (b.interval_s || '') + 's</td>' +
             '<td class="text-end"><span class="' + cvCls + '">' + (typeof b.cv === 'number' ? b.cv.toFixed(3) : b.cv) + '</span></td></tr>';
    }).join('');
    sections.push(
      '<div class="p-3 border-bottom">' +
      '<h6 class="fw-semibold mb-2 small text-uppercase text-muted" style="color:#fd7e14!important">Beaconing Flows (' + beacons.length + ')</h6>' +
      '<div class="table-responsive"><table class="table table-sm mb-0">' +
      '<thead class="table-light"><tr><th>Src</th><th>Dst</th><th class="text-end">Port</th><th class="text-end">Interval</th><th class="text-end">CV</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div></div>'
    );
  }

  // ── SMB ───────────────────────────────────────────────────────
  var smbPairs = (d.smb || []).filter(function(p) {
    return p.src === ip || p.dst === ip;
  });
  if (smbPairs.length) {
    var rows = smbPairs.map(function(p) {
      return '<tr><td class="font-monospace small">' + _esc(p.src) + '</td>' +
             '<td class="font-monospace small">' + _esc(p.dst) + '</td>' +
             '<td class="text-end">' + (p.port || '') + '</td>' +
             '<td class="text-end">' + (p.packet_count || 0).toLocaleString() + '</td></tr>';
    }).join('');
    sections.push(
      '<div class="p-3">' +
      '<h6 class="fw-semibold mb-2 small text-uppercase text-muted">SMB Traffic (' + smbPairs.length + ')</h6>' +
      '<div class="table-responsive"><table class="table table-sm mb-0">' +
      '<thead class="table-light"><tr><th>Src</th><th>Dst</th><th class="text-end">Port</th><th class="text-end">Packets</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div></div>'
    );
  }

  if (!sections.length) {
    return '<div class="p-4 text-center text-muted">' +
      'No detailed activity found for <code>' + _esc(ip) + '</code> in this capture.' +
      '</div>';
  }
  return sections.join('');
}

// ── Header severity badge → IOC tab nav ─────────────────────────
function initSeverityBadgeNav() {
  document.querySelectorAll('.sev-nav-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var sev = btn.dataset.sev;

      // Switch to IOCs tab
      var iocsTabBtn = document.getElementById('iocs-tab-btn');
      if (iocsTabBtn) bootstrap.Tab.getOrCreateInstance(iocsTabBtn).show();

      // Activate the matching severity filter button
      document.querySelectorAll('.ioc-sev-btn').forEach(function(b) {
        b.classList.toggle('active', b.dataset.sev === sev);
      });

      // Apply filter directly (avoids re-triggering the click handler)
      document.querySelectorAll('#iocTable tbody tr.ioc-row').forEach(function(row) {
        row.classList.toggle('d-none', row.dataset.sev !== sev);
      });
    });
  });
}

// ── Global search (mirrors into all per-tab search boxes) ────────
function initGlobalSearch() {
  var input = document.getElementById('global-search');
  if (!input) return;

  input.addEventListener('input', function() {
    var val = this.value;
    ['ioc-search', 'dns-search', 'http-search', 'host-search'].forEach(function(id) {
      var el = document.getElementById(id);
      if (el) {
        el.value = val;
        el.dispatchEvent(new Event('input'));
      }
    });
  });
}

// ── Threat Graph (lazy — builds on first tab show) ──────────────
function initThreatGraph() {
  var tabBtn = document.getElementById('threat-graph-tab-btn');
  if (!tabBtn) return;
  var built = false;
  tabBtn.addEventListener('shown.bs.tab', function () {
    if (built) return;
    built = true;
    _buildThreatGraph();
  });
}

function _buildThreatGraph() {
  var container = document.getElementById('threat-graph');
  if (!container || !window.REPORT_DATA || typeof vis === 'undefined') return;

  var d = window.REPORT_DATA;
  var nodesArr = [];
  var edgesArr = [];
  var nodeSet  = {};   // id → color object (for highlight restore)
  var eid      = 0;

  // ── Colour palette ────────────────────────────────────────────────
  var C = {
    internal:   { background:'#1d4ed8', border:'#60a5fa',  highlight:{ background:'#3b82f6', border:'#93c5fd' } },
    external:   { background:'#374151', border:'#6b7280',  highlight:{ background:'#4b5563', border:'#9ca3af' } },
    malicious:  { background:'#b91c1c', border:'#f87171',  highlight:{ background:'#dc2626', border:'#fca5a5' } },
    beacon:     { background:'#b45309', border:'#fbbf24',  highlight:{ background:'#d97706', border:'#fde68a' } },
    domain:     { background:'#065f46', border:'#34d399',  highlight:{ background:'#059669', border:'#6ee7b7' } },
    flagDomain: { background:'#78350f', border:'#f59e0b',  highlight:{ background:'#92400e', border:'#fcd34d' } },
    iocCrit:    { background:'#7f1d1d', border:'#f87171',  highlight:{ background:'#991b1b', border:'#fca5a5' } },
    iocHigh:    { background:'#78350f', border:'#fbbf24',  highlight:{ background:'#92400e', border:'#fde68a' } },
    iocMed:     { background:'#713f12', border:'#fde047',  highlight:{ background:'#854d0e', border:'#fef08a' } },
    iocInfo:    { background:'#0c4a6e', border:'#67e8f9',  highlight:{ background:'#0e7490', border:'#a5f3fc' } }
  };

  // ── Node / edge builders ─────────────────────────────────────────
  function addNode(id, label, color, opts) {
    if (nodeSet[id]) return;
    nodeSet[id] = color;
    nodesArr.push(Object.assign({
      id: id, label: label, color: color,
      font: { color:'#e5e7eb', size:11, strokeWidth:2, strokeColor:'#0d1117' },
      borderWidth: 2, borderWidthSelected: 3
    }, opts || {}));
  }

  function addEdge(from, to, color, opts) {
    if (!nodeSet[from] || !nodeSet[to]) return;
    edgesArr.push(Object.assign({ id:'e'+(++eid), from:from, to:to, color:color }, opts || {}));
  }

  // ── Classify IOCs → mal IP/domain maps ──────────────────────────
  var malIps     = {};   // ip → severity
  var malDomains = {};   // domain (lower) → severity
  (d.iocs || []).forEach(function (ioc) {
    if (!ioc.value) return;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc.value)) {
      malIps[ioc.value] = ioc.severity;
    } else if ((ioc.type || '').toLowerCase().indexOf('domain') >= 0) {
      malDomains[ioc.value.toLowerCase()] = ioc.severity;
    }
  });

  var beaconIps = {};
  (d.beaconing || []).forEach(function (b) {
    if (b.src) beaconIps[b.src] = true;
    if (b.dst) beaconIps[b.dst] = true;
  });

  // ── Host nodes ───────────────────────────────────────────────────
  (d.hosts || []).forEach(function (h) {
    if (!h.ip) return;
    var isInt = (h.type === 'internal' || h.is_internal);
    var color = malIps[h.ip]    ? C.malicious
              : beaconIps[h.ip] ? C.beacon
              : isInt           ? C.internal
              :                   C.external;

    var hostname = (d.domainMap || {})[h.ip] || '';
    var label    = h.ip + (hostname ? '\n' + hostname.substring(0, 20) : '');
    var vol      = (h.packets_sent || 0) + (h.packets_received || 0);
    var sz       = Math.max(8, Math.min(28, 8 + Math.log10(vol + 1) * 5));
    var tip = '<b>' + h.ip + '</b>' + (hostname ? '<br>' + hostname : '') +
              (h.country ? '<br>Country: ' + h.country : '') +
              (h.asn_description ? '<br>' + h.asn_description : '') +
              '<br>Pkts ↑' + (h.packets_sent || 0).toLocaleString() +
              ' ↓' + (h.packets_received || 0).toLocaleString();

    addNode('ip:' + h.ip, label, color, { shape:'dot', size:sz, title:tip, _nodeType:'ip', _data:h });
  });

  // ── DNS nodes + edges ────────────────────────────────────────────
  (d.dns || []).forEach(function (q) {
    if (!q.domain) return;
    var dk   = 'domain:' + q.domain;
    var flag = malDomains[q.domain.toLowerCase()];
    var col  = flag ? C.flagDomain : C.domain;
    var lbl  = q.domain.length > 22 ? q.domain.substring(0, 20) + '…' : q.domain;
    var tip  = '<b>' + q.domain + '</b><br>Queries: ' + (q.query_count || 0) +
               ((q.resolved_ips || []).length ? '<br>Resolves: ' + q.resolved_ips.slice(0, 3).join(', ') : '') +
               (flag ? '<br><span style="color:#f87171">⚠ Flagged: ' + flag + '</span>' : '');

    addNode(dk, lbl, col, {
      shape:'box', size:10, shapeProperties:{ borderRadius:4 },
      title:tip, _nodeType:'domain', _data:q
    });

    // IP → domain (DNS query)
    (q.queried_by || []).forEach(function (src) {
      addEdge('ip:' + src, dk,
        { color:'#6b7280', opacity:0.5, highlight:'#94a3b8' },
        { dashes:[4,3], width:1,
          arrows:{ to:{ enabled:true, scaleFactor:0.4 } },
          title:'DNS query', _edgeType:'dns' });
    });

    // domain → IP (resolution)
    (q.resolved_ips || []).forEach(function (rip) {
      if (!nodeSet['ip:' + rip]) {
        addNode('ip:' + rip, rip, malIps[rip] ? C.malicious : C.external, {
          shape:'dot', size:7,
          title:'<b>' + rip + '</b><br>External (DNS resolution)',
          _nodeType:'ip', _data:{ ip:rip, type:'external' }
        });
      }
      addEdge(dk, 'ip:' + rip,
        { color:'#4b5563', opacity:0.4, highlight:'#9ca3af' },
        { dashes:[2,3], width:1,
          arrows:{ to:{ enabled:true, scaleFactor:0.35 } },
          title:'Resolves to', _edgeType:'dns_resolve' });
    });
  });

  // ── Beaconing edges ──────────────────────────────────────────────
  (d.beaconing || []).forEach(function (b) {
    if (!b.src || !b.dst) return;
    if (!nodeSet['ip:' + b.src]) addNode('ip:' + b.src, b.src, C.beacon, { shape:'dot', size:8, title:'<b>' + b.src + '</b><br>Beaconing source', _nodeType:'ip', _data:{ ip:b.src, type:'internal' } });
    if (!nodeSet['ip:' + b.dst]) addNode('ip:' + b.dst, b.dst, C.external, { shape:'dot', size:8, title:'<b>' + b.dst + '</b><br>Beacon target', _nodeType:'ip', _data:{ ip:b.dst, type:'external' } });
    addEdge('ip:' + b.src, 'ip:' + b.dst,
      { color:'#f59e0b', opacity:0.85, highlight:'#fbbf24' },
      { width:2.5, arrows:{ to:{ enabled:true, scaleFactor:0.7 } },
        title:'Beaconing · interval ' + b.interval_s + 's · CV ' + (typeof b.cv === 'number' ? b.cv.toFixed(3) : b.cv),
        _edgeType:'beacon', smooth:{ type:'curvedCW', roundness:0.2 } });
  });

  // ── SMB edges ────────────────────────────────────────────────────
  (d.smb || []).forEach(function (p) {
    if (!p.src || !p.dst) return;
    if (!nodeSet['ip:' + p.src]) addNode('ip:' + p.src, p.src, C.internal, { shape:'dot', size:8, title:'<b>' + p.src + '</b>', _nodeType:'ip', _data:{ ip:p.src, type:'internal' } });
    if (!nodeSet['ip:' + p.dst]) addNode('ip:' + p.dst, p.dst, C.internal, { shape:'dot', size:8, title:'<b>' + p.dst + '</b>', _nodeType:'ip', _data:{ ip:p.dst, type:'internal' } });
    addEdge('ip:' + p.src, 'ip:' + p.dst,
      { color:'#7c3aed', opacity:0.8, highlight:'#a78bfa' },
      { width:2, arrows:{ to:{ enabled:true, scaleFactor:0.6 } },
        title:'SMB · port ' + (p.port || 445) + ' · ' + (p.packet_count || 0).toLocaleString() + ' pkts',
        _edgeType:'smb' });
  });

  // ── HTTP edges (grouped, 2+ requests between same pair only) ─────
  var httpPairs = {};
  (d.http || []).forEach(function (r) {
    var src = r.src || r.src_ip || '';
    var dst = r.dst || r.dst_ip || '';
    if (!src || !dst || src === dst) return;
    httpPairs[src + '|' + dst] = (httpPairs[src + '|' + dst] || 0) + 1;
  });
  Object.keys(httpPairs).forEach(function (k) {
    var parts = k.split('|'), cnt = httpPairs[k];
    if (cnt < 2) return;
    addEdge('ip:' + parts[0], 'ip:' + parts[1],
      { color:'#2563eb', opacity:0.55, highlight:'#60a5fa' },
      { width:Math.min(3, 1 + Math.log10(cnt)), dashes:false,
        arrows:{ to:{ enabled:true, scaleFactor:0.5 } },
        title:'HTTP · ' + cnt + ' request' + (cnt !== 1 ? 's' : ''),
        _edgeType:'http' });
  });

  // ── IOC nodes + edges to matching IP/domain ──────────────────────
  (d.iocs || []).forEach(function (ioc, idx) {
    if (!ioc.value) return;
    var iocColor = { CRITICAL:C.iocCrit, HIGH:C.iocHigh, MEDIUM:C.iocMed, INFO:C.iocInfo }[ioc.severity] || C.iocInfo;
    var iid  = 'ioc:' + idx;
    var sv   = ioc.value || '';
    var lbl  = '⚠ ' + (sv.length > 22 ? sv.substring(0, 20) + '…' : sv);
    var tip  = '<b>IOC — ' + (ioc.severity || '') + '</b><br>Type: ' + (ioc.type || '') +
               '<br>' + sv + (ioc.description ? '<br>' + ioc.description : '');

    addNode(iid, lbl, iocColor, {
      shape:'diamond', size:12, title:tip, _nodeType:'ioc', _data:ioc,
      font:{ color:'#fff', size:10, strokeWidth:2, strokeColor:'#0d1117' }
    });

    // Connect to matching IP or domain node
    var tid = nodeSet['ip:' + ioc.value] ? 'ip:' + ioc.value
            : nodeSet['domain:' + ioc.value] ? 'domain:' + ioc.value
            : null;
    if (!tid) {
      // Try case-insensitive domain match
      var lo = ioc.value.toLowerCase();
      Object.keys(nodeSet).some(function (k) {
        if (k.startsWith('domain:') && k.slice(7).toLowerCase() === lo) { tid = k; return true; }
      });
    }
    if (tid) {
      edgesArr.push({ id:'e' + (++eid), from:iid, to:tid,
        color:{ color:'#ef4444', opacity:0.7, highlight:'#f87171' },
        dashes:[3,4], width:1.5,
        arrows:{ to:{ enabled:true, scaleFactor:0.5 } },
        title:'IOC: ' + (ioc.type || '') + ' — ' + (ioc.severity || ''),
        _edgeType:'ioc' });
    }
  });

  // ── vis DataSets + Network ───────────────────────────────────────
  var nodeDS = new vis.DataSet(nodesArr);
  var edgeDS = new vis.DataSet(edgesArr);

  var ncEl = document.getElementById('tg-node-count');
  var ecEl = document.getElementById('tg-edge-count');
  if (ncEl) ncEl.textContent = nodesArr.length;
  if (ecEl) ecEl.textContent = edgesArr.length;

  var tgNet = new vis.Network(container, { nodes:nodeDS, edges:edgeDS }, {
    layout:  { randomSeed:11 },
    physics: {
      enabled: true,
      solver:  'forceAtlas2Based',
      forceAtlas2Based: {
        gravitationalConstant:-40, centralGravity:0.005,
        springLength:130, springConstant:0.05, damping:0.5, avoidOverlap:0.8
      },
      stabilization:{ iterations:200, updateInterval:40, fit:true }
    },
    interaction:{ hover:true, tooltipDelay:150, navigationButtons:false, zoomView:true },
    nodes:{ borderWidth:2, shadow:false },
    edges:{ smooth:{ type:'continuous' }, hoverWidth:2, selectionWidth:2 }
  });

  tgNet.once('stabilizationIterationsDone', function () {
    tgNet.setOptions({ physics:{ enabled:false } });
    tgNet.fit({ animation:{ duration:500, easingFunction:'easeInOutQuad' } });
  });

  // ── Highlight state ──────────────────────────────────────────────
  var tgLit = false;

  function tgHighlight(nodeId) {
    tgLit = true;
    var connN = new Set(tgNet.getConnectedNodes(nodeId));
    var connE = new Set(tgNet.getConnectedEdges(nodeId));
    connN.add(nodeId);

    nodeDS.update(nodeDS.map(function (n) {
      var on = connN.has(n.id);
      return { id:n.id,
        color:on ? nodeSet[n.id] : { background:'#1a2332', border:'#253347' },
        font:{ color:on?'#e5e7eb':'#2d3a4a', strokeColor:'#0d1117', strokeWidth:2, size:11 },
        opacity:on ? 1 : 0.12 };
    }));
    edgeDS.update(edgeDS.map(function (e) {
      var on = connE.has(e.id);
      return { id:e.id,
        color:on ? undefined : { color:'#1a2332', opacity:0.06 },
        width:on ? Math.max(e.width || 1, 1.5) : (e.width || 1) };
    }));

    var cb = document.getElementById('tg-clear-sel');
    if (cb) cb.disabled = false;

    tgShowPanel(nodeId, connN);
    tgNet.focus(nodeId, { scale:1.05, animation:{ duration:350, easingFunction:'easeInOutQuad' } });
  }

  function tgClear() {
    if (!tgLit) return;
    tgLit = false;
    nodeDS.update(nodeDS.map(function (n) {
      return { id:n.id, color:nodeSet[n.id],
               font:{ color:'#e5e7eb', strokeColor:'#0d1117', strokeWidth:2, size:11 }, opacity:1 };
    }));
    edgeDS.update(edgeDS.map(function (e) { return { id:e.id, color:undefined, width:e.width||1 }; }));
    var cb = document.getElementById('tg-clear-sel');
    if (cb) cb.disabled = true;
    var panel = document.getElementById('tg-detail-panel');
    if (panel) panel.style.display = 'none';
  }

  // ── Detail panel ─────────────────────────────────────────────────
  function tgShowPanel(nodeId, connNodeSet) {
    var panel   = document.getElementById('tg-detail-panel');
    var titleEl = document.getElementById('tg-panel-title');
    var bodyEl  = document.getElementById('tg-panel-body');
    if (!panel || !bodyEl) return;

    panel.style.display = 'flex';
    panel.style.flexDirection = 'column';

    var node = nodeDS.get(nodeId);
    if (!node) return;

    // Build connected list (excluding self)
    var connList = [];
    connNodeSet.forEach(function (id) { if (id !== nodeId) connList.push(id); });

    var html = '';

    if (node._nodeType === 'ip') {
      var ip   = nodeId.replace('ip:', '');
      if (titleEl) titleEl.textContent = ip;
      var host = node._data || {};
      if (malIps[ip])    html += '<span class="badge bg-danger mb-1">IOC — ' + _esc(malIps[ip]) + '</span> ';
      if (beaconIps[ip]) html += '<span class="badge bg-warning text-dark mb-1">Beaconing</span> ';
      html += '<div class="mt-2">';
      if (host.type)             html += _tgRow('Type', _esc(host.type));
      if (host.country)          html += _tgRow('Country', _esc(host.country));
      if (host.asn_description)  html += _tgRow('ASN', _esc(host.asn_description.substring(0, 38)));
      if (host.packets_sent)     html += _tgRow('Sent', host.packets_sent.toLocaleString() + ' pkts');
      if (host.packets_received) html += _tgRow('Recv', host.packets_received.toLocaleString() + ' pkts');
      var hn = (d.domainMap || {})[ip];
      if (hn) html += _tgRow('Hostname', '<code class="text-light" style="font-size:.76rem">' + _esc(hn) + '</code>');
      html += '</div>';
      html += tgConnList(connList);
      html += '<button class="btn btn-sm btn-outline-light w-100 mt-3 tg-profile-btn" data-ip="' + _esc(ip) + '" style="font-size:.78rem">Full Profile →</button>';

    } else if (node._nodeType === 'domain') {
      var domain = nodeId.replace('domain:', '');
      if (titleEl) titleEl.textContent = domain;
      var q = node._data || {};
      html += '<code class="text-light d-block mb-2" style="word-break:break-all;font-size:.76rem">' + _esc(domain) + '</code>';
      html += '<div>';
      if (q.query_count) html += _tgRow('Queries', q.query_count);
      if ((q.flags || []).length) {
        html += _tgRow('Flags', q.flags.map(function (f) {
          return '<span class="badge bg-warning text-dark me-1" style="font-size:.68rem;font-weight:500">' + _esc(f) + '</span>';
        }).join(''));
      }
      if ((q.resolved_ips || []).length) {
        html += _tgRow('Resolves', q.resolved_ips.slice(0, 4).map(function (i) {
          return '<code class="text-light" style="font-size:.74rem">' + _esc(i) + '</code>';
        }).join('<br>'));
      }
      html += '</div>';
      html += tgConnList(connList);
      html += '<a href="https://www.virustotal.com/gui/domain/' + encodeURIComponent(domain) + '" target="_blank" rel="noopener" class="btn btn-sm btn-outline-light w-100 mt-3" style="font-size:.78rem">VirusTotal →</a>';

    } else if (node._nodeType === 'ioc') {
      var ioc = node._data || {};
      if (titleEl) titleEl.textContent = 'IOC';
      var sevCls = { CRITICAL:'danger', HIGH:'high', MEDIUM:'warning text-dark', INFO:'info text-dark' }[ioc.severity] || 'secondary';
      html += '<span class="badge bg-' + sevCls + ' mb-1">' + _esc(ioc.severity || '') + '</span>';
      html += '<div class="mt-1">' + _tgRow('Type', _esc(ioc.type || '')) + '</div>';
      html += '<code class="text-light d-block my-2" style="word-break:break-all;font-size:.76rem">' + _esc(ioc.value || '') + '</code>';
      if (ioc.description) html += '<div class="text-muted mb-2" style="font-size:.76rem">' + _esc(ioc.description) + '</div>';
      html += tgConnList(connList);
      var vtType = /^\d{1,3}(\.\d{1,3}){3}$/.test(ioc.value || '') ? 'ip-address' : 'domain';
      html += '<a href="https://www.virustotal.com/gui/' + vtType + '/' + encodeURIComponent(ioc.value || '') + '" target="_blank" rel="noopener" class="btn btn-sm btn-outline-light w-100 mt-3" style="font-size:.78rem">VirusTotal →</a>';
    }

    bodyEl.innerHTML = html;
  }

  function _tgRow(label, value) {
    return '<div class="d-flex justify-content-between align-items-start gap-2 mb-1">' +
           '<span class="text-muted flex-shrink-0" style="font-size:.74rem">' + label + '</span>' +
           '<span class="text-end text-light" style="font-size:.78rem;word-break:break-word">' + value + '</span>' +
           '</div>';
  }

  function tgConnList(ids) {
    if (!ids.length) return '';
    var html = '<div class="tg-section-label mt-3 mb-1">Connections (' + ids.length + ')</div>';
    html += '<div class="tg-conn-list">';
    ids.slice(0, 14).forEach(function (nid) {
      var n = nodeDS.get(nid);
      if (!n) return;
      var icon = { ip:'💻', domain:'🌐', ioc:'⚠' }[n._nodeType] || '·';
      var raw  = n._nodeType === 'ip'     ? nid.replace('ip:', '')
               : n._nodeType === 'domain' ? nid.replace('domain:', '')
               : ((n._data || {}).value || nid);
      var lbl  = raw.length > 24 ? raw.substring(0, 22) + '…' : raw;
      html += '<div class="tg-conn-item" data-nid="' + _esc(nid) + '">' +
              '<span class="tg-conn-icon">' + icon + '</span>' +
              '<span class="tg-conn-label">' + _esc(lbl) + '</span>' +
              '</div>';
    });
    if (ids.length > 14) html += '<div class="text-muted" style="font-size:.7rem;padding:3px 0">…and ' + (ids.length - 14) + ' more</div>';
    html += '</div>';
    return html;
  }

  // ── Events ───────────────────────────────────────────────────────
  tgNet.on('click', function (p) {
    if (!p.nodes.length) { tgClear(); return; }
    tgHighlight(p.nodes[0]);
  });

  tgNet.on('doubleClick', function (p) {
    if (!p.nodes.length) return;
    var n = nodeDS.get(p.nodes[0]);
    if (!n) return;
    if (n._nodeType === 'ip') {
      var a = document.createElement('a');
      a.dataset.ip = p.nodes[0].replace('ip:', '');
      a.classList.add('ip-link'); a.href = '#';
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
    } else {
      var val = n._nodeType === 'domain' ? p.nodes[0].replace('domain:', '') : ((n._data || {}).value || '');
      if (!val) return;
      var isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(val);
      window.open('https://www.virustotal.com/gui/' + (isIp ? 'ip-address' : 'domain') + '/' + encodeURIComponent(val), '_blank', 'noopener');
    }
  });

  // Click on connection list item → jump to that node
  var panel = document.getElementById('tg-detail-panel');
  if (panel) {
    panel.addEventListener('click', function (e) {
      var item = e.target.closest('[data-nid]');
      if (item) {
        tgHighlight(item.dataset.nid);
        tgNet.focus(item.dataset.nid, { scale:1.15, animation:{ duration:300, easingFunction:'easeInOutQuad' } });
        return;
      }
      // Full Profile button
      var pb = e.target.closest('.tg-profile-btn');
      if (pb && pb.dataset.ip) {
        var a = document.createElement('a');
        a.dataset.ip = pb.dataset.ip; a.classList.add('ip-link'); a.href = '#';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
      }
    });
  }

  // ── Search ────────────────────────────────────────────────────────
  var srch = document.getElementById('tg-search');
  if (srch) {
    srch.addEventListener('input', function () {
      var term = this.value.trim().toLowerCase();
      if (!term) { tgClear(); return; }
      var hits = [];
      nodeDS.forEach(function (n) {
        if ((n.id || '').toLowerCase().includes(term) || (n.label || '').toLowerCase().includes(term)) hits.push(n.id);
      });
      if (!hits.length) return;
      if (hits.length === 1) { tgHighlight(hits[0]); return; }

      tgLit = true;
      var hitSet = {};
      hits.forEach(function (id) { hitSet[id] = true; });
      nodeDS.update(nodeDS.map(function (n) {
        var on = !!hitSet[n.id];
        return { id:n.id, color:on ? nodeSet[n.id] : { background:'#1a2332', border:'#253347' },
                 font:{ color:on?'#e5e7eb':'#2d3a4a', strokeColor:'#0d1117', strokeWidth:2, size:11 }, opacity:on?1:0.12 };
      }));
      var cb = document.getElementById('tg-clear-sel');
      if (cb) cb.disabled = false;
      tgNet.fit({ nodes:hits, animation:{ duration:350, easingFunction:'easeInOutQuad' } });
    });
  }

  // ── Type filter ──────────────────────────────────────────────────
  document.querySelectorAll('.tg-type-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.tg-type-btn').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      tgClear();
      var type = btn.dataset.type;

      if (type === 'all') {
        nodeDS.update(nodeDS.map(function (n) { return { id:n.id, hidden:false }; }));
        edgeDS.update(edgeDS.map(function (e) { return { id:e.id, hidden:false }; }));
      } else {
        var showN = {};
        nodeDS.forEach(function (n) {
          var rawIp = n.id.replace('ip:', '');
          var show  = (type === 'ip'      && n._nodeType === 'ip')
                   || (type === 'domain'  && n._nodeType === 'domain')
                   || (type === 'ioc'     && n._nodeType === 'ioc')
                   || (type === 'beacon'  && n._nodeType === 'ip' && !!beaconIps[rawIp]);
          showN[n.id] = show;
        });
        nodeDS.update(nodeDS.map(function (n) { return { id:n.id, hidden:!showN[n.id] }; }));
        edgeDS.update(edgeDS.map(function (e) { return { id:e.id, hidden:!(showN[e.from] && showN[e.to]) }; }));
      }
      tgNet.fit({ animation:{ duration:300, easingFunction:'easeInOutQuad' } });
    });
  });

  // ── Layout switch ────────────────────────────────────────────────
  var lyEl = document.getElementById('tg-layout');
  if (lyEl) {
    lyEl.addEventListener('change', function () {
      if (this.value === 'hierarchical') {
        tgNet.setOptions({ layout:{ hierarchical:{ enabled:true, direction:'UD', sortMethod:'directed', levelSeparation:120 } }, physics:{ enabled:false } });
      } else {
        tgNet.setOptions({ layout:{ hierarchical:{ enabled:false } }, physics:{ enabled:true, stabilization:{ iterations:100 } } });
      }
    });
  }

  // ── Reset + clear buttons ─────────────────────────────────────────
  var resetBtn = document.getElementById('tg-reset-btn');
  if (resetBtn) resetBtn.addEventListener('click', function () {
    tgClear();
    tgNet.fit({ animation:{ duration:400, easingFunction:'easeInOutQuad' } });
  });
  var clearBtn = document.getElementById('tg-clear-sel');
  if (clearBtn) clearBtn.addEventListener('click', tgClear);
  var panelClose = document.getElementById('tg-panel-close');
  if (panelClose) panelClose.addEventListener('click', tgClear);

  // ── Tab re-show: fix sizing ──────────────────────────────────────
  var tgTabBtn = document.getElementById('threat-graph-tab-btn');
  if (tgTabBtn) {
    tgTabBtn.addEventListener('shown.bs.tab', function () {
      tgNet.redraw();
      tgNet.fit({ animation:{ duration:400, easingFunction:'easeInOutQuad' } });
    });
  }

  // ── Empty state ──────────────────────────────────────────────────
  if (!nodesArr.length) {
    var empEl  = document.getElementById('tg-empty');
    var cardEl = document.getElementById('threat-graph-card');
    if (empEl)  empEl.classList.remove('d-none');
    if (cardEl) cardEl.style.display = 'none';
  }
}

// ── Boot ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  initTimeline();
  initDarkMode();
  initCharts();
  initPacketTimeline();
  initGeoMap();
  initSortableTables();
  initExpandableRows();
  initCopyIOCs();
  initExportCSV();
  initHistoryTab();
  initIocFilterBar();
  initHostsFilterBar();
  initDnsFilter();
  initHttpFilterBar();
  initIpModal();
  initSeverityBadgeNav();
  initGlobalSearch();
  initThreatGraph();
});
