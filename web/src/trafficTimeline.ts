// Stored samples precede the live stream. Once live measurements start, a later
// history refresh must not replace them with coarser averages or fill outages.
export function continueTrafficHistory<T>(history:T[], live:T[], at:(point:T)=>number, from:number, to:number):T[] {
 const first=live.length?at(live[0]):Infinity;
 return [...history.filter(p=>at(p)<first),...live].filter(p=>at(p)>=from&&at(p)<=to);
}
