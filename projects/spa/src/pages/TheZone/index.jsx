import { useEffect, useRef, useState } from "react"

function Canvas(props) {

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

	console.log(["stop"])
	context.stroke()
    }

    function draw(e) {
	if (!active) {
	    return
	}

        if (! context) {
	    console.log(["no ctx"])
            return
        }

	let offset = current.getBoundingClientRect()
	
	console.log([offset])
	context.lineWidth = 5
	context.lineCap = "round"
	context.lineTo(e.clientX - offset.left, e.clientY - offset.top)
	context.stroke()
    }
    
    return <canvas ref={canvasRef}
                   width={props.width}
                   height={props.height}
		   onMouseDown={start}
		   onMouseUp={stop}
		   onMouseMove={draw}
		   style={{touchAction: "none", border: "1px dashed #000"}}
	   />
}

export default function TheZone() {

    return (
        <>
            <h2>Welcome to The Zone!</h2>
            <section className="container">
		<Canvas id="focused" width="500" height="500" />
            </section>
        </>
    )
}
