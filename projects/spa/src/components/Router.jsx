import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import Landing from '../pages/Landing'


const routes = createBrowserRouter([
    {
        path: "/",
        element: <Landing />
    }
])

export default function AppRouter() {
    return <RouterProvider router={routes} />
}

