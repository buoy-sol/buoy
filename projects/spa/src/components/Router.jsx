import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import Landing from '../pages/Landing';
import TheZone from '../pages/TheZone';


const routes = createBrowserRouter([
    {
        path: "/",
        element: <Landing />
    },
    {
        path: "/zone",
        element: <TheZone />
    }
]);

export default function AppRouter() {
    return <RouterProvider router={routes} />;
}

