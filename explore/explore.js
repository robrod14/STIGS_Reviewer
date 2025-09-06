document.addEventListener("DOMContentLoaded", () => {
    const filterRows = document.getElementById("filterRows");
    const addBtn = document.getElementById("addFilter");
    const runBtn = document.getElementById("run");
    const resultsEl = document.getElementById("results");
    const detailEl = document.getElementById("detailPanels");


    const fields = ["title", "status", "severity", "stig_id", "description"];
    const ops = ["contains", "not_contains", "equals", "regex"];


    addBtn.onclick = () => {
        const row = document.createElement("div");
        const fieldSel = document.createElement("select");
        fields.forEach(f => {
            const o = document.createElement("option");
            o.value = f; o.textContent = f;
            fieldSel.appendChild(o);
        });
        const opSel = document.createElement("select");
        ops.forEach(oVal => {
            const o = document.createElement("option");
            o.value = oVal; o.textContent = oVal;
            opSel.appendChild(o);
        });
        const valInput = document.createElement("input");
        row.appendChild(fieldSel);
        row.appendChild(opSel);
        row.appendChild(valInput);
        filterRows.appendChild(row);
    };


    runBtn.onclick = async () => {
        const filters = [];
        filterRows.querySelectorAll("div").forEach(row => {
            const [fieldSel, opSel, valInput] = row.children;
            filters.push({field: fieldSel.value, op: opSel.value, value: valInput.value});
        });
        const resp = await fetch("/explore/api/search", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({filters})
        });
        const data = await resp.json();
        resultsEl.innerHTML = "";
        data.results.forEach(r => {
            const li = document.createElement("li");
            li.textContent = `${r.stig_id} | ${r.title} | ${r.severity}`;
            li.onclick = async () => {
                const detailResp = await fetch(`/explore/api/item/${r.id}`);
                const detail = await detailResp.json();
                detailEl.innerHTML = `
                    <h2>${detail.title}</h2>
                    <p><b>Description:</b> ${detail.description || ''}</p>
                    <p><b>Check:</b> ${detail.check_text || ''}</p>
                    <p><b>Fix:</b> ${detail.fix_text || ''}</p>
                    <p><b>Finding Details:</b> ${detail.finding_details || ''}</p>
                    <p><b>Comments:</b> ${detail.comments || ''}</p>
                    <p><b>NIST/CCI/AP:</b> ${detail.nist_cci || ''}</p>
                    <p><b>Severity:</b> ${detail.severity}</p>
                    <p><b>Status:</b> ${detail.status}</p>
                `;
            };
            resultsEl.appendChild(li);
        });
    };
});
