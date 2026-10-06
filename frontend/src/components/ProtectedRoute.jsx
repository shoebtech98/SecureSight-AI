import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';

const ProtectedRoute = () => {
  const token = localStorage.getItem('token') || sessionStorage.getItem('token');
  const location = useLocation();

  // If there's no JWT, redirect to the login page
  if (!token) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Otherwise, render the active child routes
  return <Outlet />;
};

export default ProtectedRoute;
