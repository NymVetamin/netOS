import { ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";

const MIN = 0.5, MAX = 4;
const initial = { x: 0, y: 0, scale: 1 };

export function MapViewport({ width, height, background, children, overlay }: { width: number; height: number; background?: ReactNode; children: ReactNode; overlay?:ReactNode }) {
  const svg = useRef<SVGSVGElement>(null);
  const [view, setView] = useState(initial);
  const canvas = useRef<HTMLDivElement>(null);
  const [canvasHeight,setCanvasHeight]=useState(320);
  const pending = useRef(initial);
  const frame = useRef<number>();
  const updateView = (next: typeof initial) => {
    pending.current=next;
    if(frame.current===undefined) frame.current=requestAnimationFrame(()=>{frame.current=undefined;setView(pending.current)});
  };
  useEffect(()=>()=>{if(frame.current!==undefined)cancelAnimationFrame(frame.current)},[]);
  useLayoutEffect(()=>{
    const el=canvas.current;if(!el)return;
    const fit=()=>{
      const rect=el.getBoundingClientRect();
      const scale=el.clientWidth>0?rect.width/el.clientWidth:1;
      const available=(window.innerHeight-rect.top-24)/(scale || 1);
      setCanvasHeight(Math.max(240,Math.min(Math.max(420,el.clientWidth*height/width),available)));
    };
    fit();const observer=new ResizeObserver(fit);
    observer.observe(el.parentElement || el);
    window.addEventListener("resize",fit);
    return()=>{observer.disconnect();window.removeEventListener("resize",fit)};
  },[width,height]);
  const [dragging, setDragging] = useState(false);
  const gesture = useRef<{ id: number; x: number; y: number; lastX: number; lastY: number; moved: boolean }>();
  const suppressClick = useRef(false);
  const point = (x: number, y: number) => {
    const matrix = svg.current?.getScreenCTM();
    return matrix ? new DOMPoint(x, y).matrixTransform(matrix.inverse()) : null;
  };
  const zoom = (factor: number, x: number, y: number) => {
    const v=pending.current;
    const scale = Math.max(MIN, Math.min(MAX, v.scale * factor));
    const ratio = scale / v.scale;
    updateView({ scale, x: x - (x - v.x) * ratio, y: y - (y - v.y) * ratio });
  };
  useEffect(() => {
    const el = svg.current;
    if (!el) return;
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      if (gesture.current) return;
      const p = point(event.clientX, event.clientY);
      const delta = event.deltaY * (event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? el.clientHeight : 1);
      if (p) zoom(Math.exp(-Math.max(-300, Math.min(300, delta)) * 0.002), p.x, p.y);
    };
    el.addEventListener("wheel", wheel, { passive: false });
    return () => el.removeEventListener("wheel", wheel);
  }, []);
  const finish = () => {
    gesture.current = undefined;
    setDragging(false);
  };
  return <>
    <div className="map-toolbar" role="group" aria-label="Управление картой">
      <button className="btn" type="button" aria-label="Уменьшить карту" disabled={view.scale <= MIN} onClick={() => zoom(1 / 1.25, width / 2, height / 2)}>−</button>
      <span className="mono" aria-label="Масштаб карты">{Math.round(view.scale * 100)}%</span>
      <button className="btn" type="button" aria-label="Увеличить карту" disabled={view.scale >= MAX} onClick={() => zoom(1.25, width / 2, height / 2)}>+</button>
      <button className="btn" type="button" onClick={() => updateView(initial)}>Показать всю карту</button>
      <span className="hint">Колёсико — масштаб · Потяните карту для перемещения</span>
    </div>
    <div ref={canvas} className="map-canvas" style={{height:canvasHeight}}>
      {background && <svg className="map-edges" viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
        <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>{background}</g>
      </svg>}
      <svg ref={svg} viewBox={`0 0 ${width} ${height}`} role="group" aria-label="Схема сети"
        className={dragging ? "map-nodes map-dragging" : "map-nodes"}
        onPointerDown={e => {
          if (e.button !== 0 || !e.isPrimary) return;
          suppressClick.current = false;
          gesture.current = { id: e.pointerId, x: e.clientX, y: e.clientY, lastX: e.clientX, lastY: e.clientY, moved: false };
        }}
        onPointerMove={e => {
          const g = gesture.current;
          if (!g || g.id !== e.pointerId) return;
          if (!g.moved && Math.hypot(e.clientX - g.x, e.clientY - g.y) < 5) return;
          const before = point(g.lastX, g.lastY), after = point(e.clientX, e.clientY);
          if (!before || !after) return;
          g.moved = true;
          suppressClick.current = true;
          e.currentTarget.setPointerCapture(e.pointerId);
          setDragging(true);
          const v=pending.current;
          updateView({ ...v, x: v.x + after.x - before.x, y: v.y + after.y - before.y });
          g.lastX = e.clientX; g.lastY = e.clientY;
        }}
        onPointerUp={finish} onPointerCancel={finish} onLostPointerCapture={finish}
        onPointerLeave={() => { if (!gesture.current?.moved) finish(); }}
        onClickCapture={e => {
          if (suppressClick.current && e.detail !== 0) { e.preventDefault(); e.stopPropagation(); }
        }}>
        <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>{children}</g>
      </svg>
      {overlay}
    </div>
  </>;
}
