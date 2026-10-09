const keyFor = (userId) => `securesight:profile-photo:${userId}`;

export function getProfilePhoto(userId) {
  if (!userId) return null;
  try {
    return localStorage.getItem(keyFor(userId));
  } catch {
    return null;
  }
}

export function setProfilePhoto(userId, imageData) {
  if (!userId) throw new Error('Your account is still loading. Please try again.');
  if (imageData) localStorage.setItem(keyFor(userId), imageData);
  else localStorage.removeItem(keyFor(userId));
  window.dispatchEvent(new CustomEvent('securesight:profile-updated', {
    detail: { userId, imageData },
  }));
}
