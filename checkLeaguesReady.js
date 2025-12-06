// Funzione per controllare se tutti i campionati sono pronti per il turno
// (da importare e usare in server.js)
// Puoi integrarla con le API football-data.org o con dati locali

/**
 * Controlla se tutti i campionati hanno una giornata programmata nello stesso intervallo (es. stesso weekend)
 * @param {Object} leagues Oggetto: { 'Serie A': [date1, date2, ...], ... }
 * @returns {Object} { ready: boolean, nextMatchDay: Date|null, details: { [league]: Date|null } }
 */
export function checkAllLeaguesReady(leagues) {
  // leagues: { 'Serie A': [date1, date2, ...], ... }
  // Trova la prima data utile per ogni campionato
  const firstDates = Object.entries(leagues).map(([league, dates]) => {
    // Prendi la prima data futura
    const now = new Date();
    const futureDates = dates.map(d => new Date(d)).filter(d => d > now);
    return { league, date: futureDates.length > 0 ? futureDates[0] : null };
  });
  // Se almeno un campionato non ha una data, non si può partire
  if (firstDates.some(fd => !fd.date)) {
    return { ready: false, nextMatchDay: null, details: Object.fromEntries(firstDates.map(fd => [fd.league, fd.date])) };
  }
  // Trova la data più "tarda" tra tutte
  const maxDate = new Date(Math.max(...firstDates.map(fd => fd.date.getTime())));
  // Tutte le date devono essere nello stesso weekend/intervallo (es. max 3 giorni di differenza)
  const allClose = firstDates.every(fd => Math.abs(fd.date - maxDate) <= 3 * 24 * 60 * 60 * 1000);
  return {
    ready: allClose,
    nextMatchDay: allClose ? maxDate : null,
    details: Object.fromEntries(firstDates.map(fd => [fd.league, fd.date]))
  };
}
