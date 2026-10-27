// Spoken audio for the stress bank. ElevenLabs once (ELEVENLABS_API_KEY in .env), then the saved mp3 in ./audio forever,
// so a run costs no voice credits. No key and no saved copy → the Mac's own voices, so the suite always runs.
// Returns 16 kHz mono 16-bit PCM, the same as Electron streams.
//   node test/stress/voice.js --build    makes every line of the bank (skips what is saved)
require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });
const { execFileSync } = require('child_process');
const crypto = require('crypto'), fs = require('fs'), os = require('os'), path = require('path');

const DIR = path.join(__dirname, 'audio');
const VOICES_FILE = path.join(DIR, 'voices.json');
// Slot → preferred ElevenLabs premade voices (first one the account has wins), and the Mac fallback.
const SLOTS = {
  us_m: { pick: ['Brian', 'Eric', 'Chris'], mac: 'Fred' },
  us_f: { pick: ['Jessica', 'Sarah', 'Aria'], mac: 'Samantha' },
  uk_m: { pick: ['George', 'Daniel'], mac: 'Daniel' },
  uk_f: { pick: ['Alice', 'Lily', 'Charlotte'], mac: 'Moira' },
  au_m: { pick: ['Charlie'], mac: 'Karen' },
  us_m2: { pick: ['Chris', 'Roger', 'Will'], mac: 'Ralph' },
  us_f2: { pick: ['Sarah', 'Laura', 'Matilda'], mac: 'Tessa' },
  you: { pick: ['Bill', 'Roger', 'Adam'], mac: 'Rishi' },
};
const key = () => (process.env.ELEVENLABS_API_KEY || '').trim();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xh-voice-'));
let voices = fs.existsSync(VOICES_FILE) ? JSON.parse(fs.readFileSync(VOICES_FILE, 'utf8')) : null;

async function resolveVoices() {
  if (voices) return voices;
  const r = await fetch('https://api.elevenlabs.io/v1/voices', { headers: { 'xi-api-key': key() } });
  if (!r.ok) throw new Error('ElevenLabs voices: HTTP ' + r.status + ' (is ELEVENLABS_API_KEY right?)');
  const list = (await r.json()).voices || [];
  voices = {};
  for (const [slot, { pick }] of Object.entries(SLOTS)) {
    const v = pick.map(n => list.find(x => x.name.split(/\s|-/)[0] === n)).find(Boolean) || list[Object.keys(voices).length % list.length];
    voices[slot] = { id: v.voice_id, name: v.name };
  }
  fs.writeFileSync(VOICES_FILE, JSON.stringify(voices, null, 2));
  return voices;
}

const DEFAULT_MODEL = 'eleven_flash_v2_5';
const file = (slot, text, model) => path.join(DIR, slot + (model && model !== DEFAULT_MODEL ? '-' + model : '') + '-' + crypto.createHash('sha1').update(text).digest('hex').slice(0, 12) + '.mp3');
const decode = src => { // any audio file → 16 kHz mono PCM
  const wav = path.join(tmp, Math.random().toString(36).slice(2) + '.wav');
  execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', src, wav]);
  const b = fs.readFileSync(wav); fs.rmSync(wav); return b.slice(b.indexOf('data') + 8);
};

async function make(slot, text, model = DEFAULT_MODEL) {
  const out = file(slot, text, model);
  if (fs.existsSync(out)) return { out, made: false };
  const v = (await resolveVoices())[slot];
  const r = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${v.id}?output_format=mp3_22050_32`, {
    method: 'POST', headers: { 'xi-api-key': key(), 'content-type': 'application/json' },
    body: JSON.stringify(Object.assign({ text, model_id: model }, model === DEFAULT_MODEL ? { voice_settings: { stability: 0.45, similarity_boost: 0.75 } } : {})),
  });
  if (!r.ok) throw new Error(`ElevenLabs TTS (${slot}): HTTP ${r.status} ${(await r.text()).slice(0, 160)}`);
  fs.writeFileSync(out, Buffer.from(await r.arrayBuffer()));
  return { out, made: true };
}

const used = { eleven: 0, mac: 0 };
async function pcm(slot, text, model = DEFAULT_MODEL) {
  const saved = file(slot, text, model);
  if (fs.existsSync(saved)) { used.eleven++; return decode(saved); }
  if (key()) { await make(slot, text, model); used.eleven++; return decode(saved); }
  used.mac++; // fallback: the Mac voice for this slot
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff');
  execFileSync('say', ['-v', SLOTS[slot].mac, '-o', aiff, text]);
  const b = decode(aiff); fs.rmSync(aiff); return b;
}

// Every spoken line in the bank as [slot, text].
function lines(scenarios) {
  const out = [];
  for (const s of scenarios) for (const l of s.lines) {
    if (typeof l === 'string') out.push([s.voice, l]);
    else if (l.ask) out.push([s.voice, l.ask]);
    else if (l.t) out.push([l.v, l.t]);
    else if (l.you) out.push(['you', l.you]);
  }
  return out;
}

module.exports = { pcm, lines, used, SLOTS };

if (require.main === module && process.argv.includes('--build')) (async () => {
  if (!key()) { console.error('No ELEVENLABS_API_KEY in .env'); process.exit(2); }
  const { SCENARIOS } = require('./bank');
  const all = lines(SCENARIOS); let made = 0, kept = 0;
  for (const [slot, text] of all) { const r = await make(slot, text); r.made ? made++ : kept++; }
  console.log(`voices: ${Object.entries(voices).map(([s, v]) => s + '=' + v.name).join(', ')}`);
  console.log(`${made} lines made, ${kept} already saved, ${all.length} total`);
})().catch(e => { console.error(e.message); process.exit(1); });
