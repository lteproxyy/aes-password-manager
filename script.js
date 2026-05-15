/* =========================================================
   HIER KANNST DU ALLES ÄNDERN:
   - Name
   - Spitzname
   - Startdatum
   - Liebessätze
   - schönste Momente
   - finale Nachricht
   - Mini-Texte
   - Songtitel
   ========================================================= */

const personName = "Sara";
const nickname = "Dîlemin";
const startDate = "2026-01-13";

// SONGTITEL ÄNDERN:
const songTitle = "Lovers Rock - TV Girl";

const loveReasons = [
  "du malst meine graue welt bunt",
  "du bist die erste und letzte frau in meinem leben mein alles",
  "du bist die tollste, hübscheste, gebildetste, intelligenteste, sympathischste und perfekteste frau die auf dieser welt lebt",
  "ich vermisse jeden moment den ich ohne dich erlebe",
  "az jî te hazdekim dîlemin",
  "du machst jeden noch so langweiligen moment so schön und wertvoll",
  "ich liebe es wie wir immer zusammen lachen",
  "immer wenn ich in meinem zimmer bin vermisse ich dich ein stück mehr",
  "ich liebe dein lachen so sehr und genieße jede sekunde davon",
  "oh mein baby",
  "du bist der einzige mensch bei dem ich mich komplett wohl fühle und dem ich 100% vertraue",
  "versprochen du für immer",
  "ich bin immer für dich da mein herz",

  // Weitere Liebessätze hier hinzufügen:
  // "dein neuer satz",
];

const bestMoments = [
  "die ersten wintertage bei -10°, wo ich dir meine jacke gegeben habe",
  "wo wir nachts bis um 5:00 geschrieben haben obwohl wir am nächsten tag schule hatten",
  "jeder augenkontakt mit dir",
  "wo ich realisiert habe wie sehr ich dich liebe",
  "unsere momente wo wir uns einfach komplett dumm verhalten und uns tot lachen",
  "dein lächeln",
  "die momente wo wir nur füreinander sind ohne jemand anderen",
  "wenn ich dich rage und du es gar nicht lustig findest",
  "immer wenn wir bei mir zusammen sind und kochen",
  "die zeit mit dir die so schnell vergeht aber die schönste ist die ich jemals erlebt habe",
  "wenn wir einfach nebeneinander liegen und uns küssen",
  "unsere umarmungen",
  "wenn wir uns gegenseitig nerven aber trotzdem lachen und uns lieben",
  "im unterricht wenn ich schreie dass ich dich liebe",

  // Weitere Erinnerungen hier hinzufügen:
  // "deine neue erinnerung",
];

const finalMessage = [
  "ich könnte dir tausend gründe geben warum ich dich liebe",
  "aber ehrlich herz",
  "der wichtigste grund bist einfach du ❤️",
];

const finalSignature = "für immer dein mensch";

const miniTexts = {
  counterTitle: "seit dem 13.01.2026 bist du mein lieblingsmensch ❤️",
  reasonIdle: "drück auf den knopf, ich hab da paar sachen gesammelt wa dikka ❤️",
  memoryIdle: "hier wohnen unsere kleinen momente, die ich nie vergessen will ✨",
  musicReady: "bereit, sobald du auf musik drückst.",
  musicPlaying: "läuft gerade für dich.",
  musicPaused: "pausiert, aber die vibes bleiben.",
  musicMissing: "song.mp3 fehlt noch, aber alles ist bereit ❤️",
};

/* =========================================================
   Ab hier funktioniert die Seite.
   ========================================================= */

const introScreen = document.querySelector("#introScreen");
const appShell = document.querySelector("#appShell");
const openButton = document.querySelector("#openButton");
const introBubbles = Array.from(document.querySelectorAll("[data-intro-step]"));
const introHello = document.querySelector("#introHello");
const introNickname = document.querySelector("#introNickname");

const heroHello = document.querySelector("#heroHello");
const heroNickname = document.querySelector("#heroNickname");
const counterTitle = document.querySelector("#counterTitle");
const daysCount = document.querySelector("#daysCount");
const hoursCount = document.querySelector("#hoursCount");
const minutesCount = document.querySelector("#minutesCount");
const togetherLine = document.querySelector("#togetherLine");

const reasonButton = document.querySelector("#reasonButton");
const reasonText = document.querySelector("#reasonText");
const reasonCard = document.querySelector("#reasonCard");

const memoryButton = document.querySelector("#memoryButton");
const memoryText = document.querySelector("#memoryText");
const memoryCard = document.querySelector("#memoryCard");

const finalePanel = document.querySelector("#finalePanel");
const finaleText = document.querySelector("#finaleText");
const finaleSignature = document.querySelector("#finaleSignature");

const musicPanel = document.querySelector("#musicPanel");
const musicButton = document.querySelector("#musicButton");
const musicStatus = document.querySelector("#musicStatus");
const songTitleText = document.querySelector("#songTitleText");
const loveSong = document.querySelector("#loveSong");

let reasonClicks = 0;
let lastReason = "";
let lastMoment = "";
let finaleShown = false;
let currentIntroStep = 0;

function init() {
  document.title = `Warum ich dich liebe ❤️`;
  introHello.textContent = `hey ${personName.toLowerCase()},`;
  introNickname.textContent = `${nickname.toLowerCase()} ❤️`;
  heroHello.textContent = `hey ${personName.toLowerCase()},`;
  heroNickname.textContent = `${nickname.toLowerCase()} ❤️`;
  counterTitle.textContent = miniTexts.counterTitle;
  reasonText.textContent = miniTexts.reasonIdle;
  memoryText.textContent = miniTexts.memoryIdle;
  songTitleText.textContent = songTitle;
  musicStatus.textContent = miniTexts.musicReady;
  finaleText.innerHTML = finalMessage.map((line) => escapeHtml(line)).join("<br><br>");
  finaleSignature.textContent = finalSignature;

  setupIntroBubbles();
  updateCounter();
  window.setInterval(updateCounter, 1000);
}

function setupIntroBubbles() {
  currentIntroStep = 0;
  openButton.hidden = true;
  openButton.classList.remove("is-visible");

  introBubbles.forEach((bubble, index) => {
    bubble.hidden = index !== 0;
    bubble.classList.toggle("is-visible", index === 0);
    bubble.classList.remove("is-tapped");
    bubble.addEventListener("click", () => revealNextIntroBubble(index));
  });
}

function revealNextIntroBubble(index) {
  if (index !== currentIntroStep) {
    return;
  }

  const currentBubble = introBubbles[index];
  currentBubble.classList.add("is-tapped");
  createHeartBurst(currentBubble, 7, false);
  vibrate(10);

  const nextBubble = introBubbles[index + 1];
  currentIntroStep += 1;

  if (nextBubble) {
    nextBubble.hidden = false;
    window.requestAnimationFrame(() => {
      nextBubble.classList.add("is-visible");
    });
    return;
  }

  openButton.hidden = false;
  window.requestAnimationFrame(() => {
    openButton.classList.add("is-visible");
  });
  createHeartBurst(openButton, 14, true);
}

function openApp() {
  introScreen.classList.add("is-hidden");
  appShell.hidden = false;

  window.requestAnimationFrame(() => {
    appShell.classList.add("is-visible");
  });

  createHeartBurst(openButton, 24, true);

  window.setTimeout(() => {
    introScreen.hidden = true;
  }, 560);
}

function updateCounter() {
  const start = new Date(`${startDate}T00:00:00`);
  const now = new Date();
  const distance = Math.max(0, now.getTime() - start.getTime());
  const totalMinutes = Math.floor(distance / 60000);
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;

  daysCount.textContent = String(days);
  hoursCount.textContent = String(hours).padStart(2, "0");
  minutesCount.textContent = String(minutes).padStart(2, "0");
  togetherLine.textContent = `${days} tage zusammen`;
}

function showRandomReason() {
  reasonClicks += 1;
  lastReason = pickRandom(loveReasons, lastReason);
  reasonText.textContent = lastReason;
  animateCard(reasonCard);
  createHeartBurst(reasonButton, 18, false);
  vibrate(18);

  if (reasonClicks >= 10 && !finaleShown) {
    showFinale();
  }
}

function showRandomMemory() {
  lastMoment = pickRandom(bestMoments, lastMoment);
  memoryText.textContent = lastMoment;
  animateCard(memoryCard);
  createHeartBurst(memoryButton, 12, false);
  vibrate(12);
}

function showFinale() {
  finaleShown = true;
  finalePanel.hidden = false;

  window.requestAnimationFrame(() => {
    finalePanel.classList.add("is-visible");
    finalePanel.scrollIntoView({ behavior: "smooth", block: "center" });
  });

  createHeartBurst(finalePanel, 44, true);
  vibrate([35, 30, 45]);
}

function pickRandom(list, previous) {
  if (!list.length) {
    return "";
  }

  let selected = list[Math.floor(Math.random() * list.length)];

  if (list.length > 1) {
    while (selected === previous) {
      selected = list[Math.floor(Math.random() * list.length)];
    }
  }

  return selected;
}

function animateCard(card) {
  card.classList.remove("is-popping");
  void card.offsetWidth;
  card.classList.add("is-popping");
}

function createHeartBurst(origin, amount, intense) {
  const rect = origin.getBoundingClientRect();
  const startX = rect.left + rect.width / 2;
  const startY = rect.top + rect.height / 2;
  const hearts = intense ? ["❤️", "💗", "💞", "♡"] : ["❤️", "♡", "💗"];

  for (let index = 0; index < amount; index += 1) {
    const particle = document.createElement("span");
    const direction = Math.random() * Math.PI * 2;
    const distance = intense ? randomBetween(80, 190) : randomBetween(45, 125);
    const size = intense ? randomBetween(17, 30) : randomBetween(13, 22);
    const tx = Math.cos(direction) * distance;
    const ty = Math.sin(direction) * distance - randomBetween(24, 90);

    particle.className = "heart-particle";
    particle.textContent = hearts[Math.floor(Math.random() * hearts.length)];
    particle.style.setProperty("--start-x", `${startX}px`);
    particle.style.setProperty("--start-y", `${startY}px`);
    particle.style.setProperty("--tx", `${tx}px`);
    particle.style.setProperty("--ty", `${ty}px`);
    particle.style.setProperty("--rot", `${randomBetween(-50, 50)}deg`);
    particle.style.setProperty("--size", `${size}px`);
    particle.style.setProperty("--duration", `${randomBetween(850, 1450)}ms`);

    document.body.appendChild(particle);
    window.setTimeout(() => particle.remove(), 1600);
  }
}

function randomBetween(min, max) {
  return Math.random() * (max - min) + min;
}

function vibrate(pattern) {
  if ("vibrate" in navigator) {
    navigator.vibrate(pattern);
  }
}

async function toggleMusic() {
  if (!loveSong) {
    return;
  }

  if (loveSong.paused) {
    try {
      await loveSong.play();
      updateMusicState(true, miniTexts.musicPlaying);
    } catch (error) {
      updateMusicState(false, miniTexts.musicMissing);
    }
    return;
  }

  loveSong.pause();
  updateMusicState(false, miniTexts.musicPaused);
}

function updateMusicState(isPlaying, status) {
  musicPanel.classList.toggle("is-playing", isPlaying);
  musicButton.setAttribute("aria-pressed", String(isPlaying));
  musicStatus.textContent = status;
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

openButton.addEventListener("click", openApp);
reasonButton.addEventListener("click", showRandomReason);
memoryButton.addEventListener("click", showRandomMemory);
musicButton.addEventListener("click", toggleMusic);
loveSong.addEventListener("ended", () => updateMusicState(false, miniTexts.musicPaused));
loveSong.addEventListener("error", () => updateMusicState(false, miniTexts.musicMissing));

init();
