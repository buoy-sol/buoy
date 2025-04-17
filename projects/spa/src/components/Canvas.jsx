import { useEffect, useRef, useState } from "react"

export default function Canvas(props) {
                                                                       
    const canvasRef = useRef(null)
    let current = canvasRef.current
    let context = current?.getContext("2d")
                                                                       
    useEffect(function () {
        current = canvasRef.current
        if (current) {
            context = current.getContext("2d")
        }
    }, [])
                                                                       
    let active = false
                                                                       
    function start(e) {
        if (! current) {
            return
        }
                                                                       
        active = true
        context.beginPath()
    }
                                                                       
    function stop(e) {
        active = false
                                                                       
        if (! context) {
            return
        }
                                                                       
        context.stroke()
    }
                                                                       
    function draw(e) {
        if (!active) {
            return
        }
                                                                       
        if (! context) {
            return
        }
                                                                       
        let offset = current.getBoundingClientRect()
                                                                       
        context.lineWidth = 5
        context.lineCap = "round"
        context.lineTo(e.clientX - offset.left, e.clientY - offset.top)
        context.stroke()
    }
                                                                       
    return <canvas ref={canvasRef}
                   width={props.width}
                   height={props.height}
                   onPointerDown={start}
                   onPointerUp={stop}
                   onPointerMove={draw}
                   style={{
		       touchAction: "none",
		       border: `2px dashed ${props.dashes || 'red'}`
		   }}
           />
}
