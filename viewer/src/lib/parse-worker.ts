const workerCode = `
self.onmessage = function(e) {
  var msg = e.data;
  if (msg.type === 'parse') {
    try {
      self.postMessage({type:'status',text:'Parsing JSON...'});
      var data = JSON.parse(msg.text);
      var mods = data.modules || [];
      for (var i = 0; i < mods.length; i++) {
        var vts = mods[i].vtables || [];
        for (var j = 0; j < vts.length; j++) {
          var fns = vts[j].functions || [];
          for (var k = 0; k < fns.length; k++) { delete fns[k].bytes; }
        }
      }
      self.postMessage({type:'done', data: data});
    } catch(err) {
      self.postMessage({type:'error', message: err.message});
    }
  }
  if (msg.type === 'search') {
    var q = msg.query.toLowerCase().trim();
    if (!q) { self.postMessage({type:'searchResults',requestId:msg.requestId,results:[]}); return; }
    var entries = msg.entries;
    var results = [];
    for (var i = 0; i < entries.length; i++) {
      var name = entries[i][0].toLowerCase();
      if (name.includes(q)) {
        var score = 0;
        if (name === q) score = 1000;
        else if (name.startsWith(q)) score = 500 - name.length;
        else score = 200 - name.indexOf(q);
        var cat = entries[i][1];
        if (cat === 'c') score += 10;
        else if (cat === 'e') score += 5;
        results.push([i, score]);
      }
    }
    results.sort(function(a,b){ return b[1]-a[1]; });
    self.postMessage({type:'searchResults',requestId:msg.requestId,results:results.slice(0,200)});
  }
};
`

export interface ParseWorkerMessage {
  type: 'status' | 'done' | 'error' | 'searchResults'
  text?: string
  data?: unknown
  message?: string
  requestId?: number
  results?: [number, number][]
}

export function createParseWorker(): Worker {
  const blob = new Blob([workerCode], { type: 'application/javascript' })
  return new Worker(URL.createObjectURL(blob))
}
