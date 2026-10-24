document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const $ = (id) => document.getElementById(id);
  $('err').textContent = '';
  $('out').hidden = true;
  const body = {
    network_id: $('network').value.trim(),
    hostname: $('hostname').value.trim(),
    node_type: $('type').value,
    hours: Number($('hours').value),
  };
  try {
    const res = await fetch('/api/v1/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Cluster-Secret': $('secret').value },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error((data.error && data.error.message) || res.statusText);
    $('cmd').textContent = data.join_command;
    $('exp').textContent = 'Expires ' + new Date(data.expires_at).toLocaleString();
    $('out').hidden = false;
  } catch (err) {
    $('err').textContent = err.message;
  }
});
