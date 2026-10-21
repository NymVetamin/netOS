export type ChartPoint={at:number;value:number|null;gap?:number};
// Interpolate only the visible segment under the pointer. This is display
// geometry, never an additional measurement or a value written to history.
export function probeChart(points:ChartPoint[],at:number):number|null {
 let low=0,high=points.length;
 while(low<high){const mid=(low+high)>>>1;if(points[mid].at<at)low=mid+1;else high=mid;}
 const right=points[low],left=points[low-1];
 if(right?.at===at)return right.value;
 if(!left||!right||left.value==null||right.value==null)return null;
 const span=right.at-left.at;
 if(span<=0||span>Math.max(left.gap||3,right.gap||3))return null;
 return left.value+(right.value-left.value)*(at-left.at)/span;
}
