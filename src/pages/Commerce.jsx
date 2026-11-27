import React, { useEffect, useMemo, useState } from 'react';
import { commerceService } from '../services/commerceService';

const price = (cents, currency = 'USD') => new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(cents / 100);

export default function Commerce() {
  const [products, setProducts] = useState([]);
  const [cart, setCart] = useState([]);
  const [session, setSession] = useState(() => commerceService.getSession());
  const [mode, setMode] = useState('login');
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(true);

  const loadProducts = async () => {
    try { setProducts((await commerceService.listProducts()).products); }
    catch (error) { setMessage(`Catalog unavailable: ${error.message}`); }
    finally { setLoading(false); }
  };
  useEffect(() => { loadProducts(); }, []);

  const total = useMemo(() => cart.reduce((sum, item) => sum + item.price_cents * item.quantity, 0), [cart]);
  const addItem = (product) => setCart((current) => {
    const found = current.find((item) => item.id === product.id);
    return found ? current.map((item) => item.id === product.id ? { ...item, quantity: Math.min(item.quantity + 1, product.stock_quantity) } : item) : [...current, { ...product, quantity: 1 }];
  });
  const changeQuantity = (id, delta) => setCart((current) => current.flatMap((item) => item.id !== id ? [item] : item.quantity + delta > 0 ? [{ ...item, quantity: item.quantity + delta }] : []));

  const submitAuth = async (event) => {
    event.preventDefault(); setMessage('');
    try { const user = await commerceService.authenticate(mode, mode === 'signup' ? form : { email: form.email, password: form.password }); setSession(commerceService.getSession()); setMessage(`Signed in as ${user.name}.`); }
    catch (error) { setMessage(error.message); }
  };
  const checkout = async () => {
    if (!session.token) return setMessage('Sign in before placing an order.');
    if (!cart.length) return;
    try { const { order } = await commerceService.createOrder(cart.map(({ id, quantity }) => ({ productId: id, quantity })), session.token); setCart([]); setMessage(`Order ${order.id.slice(0, 8)} created successfully.`); loadProducts(); }
    catch (error) { setMessage(error.message); }
  };

  return <div className="page-content-padded commerce-page">
    <section className="commerce-heading">
      <div><p className="eyebrow">Connected commerce API</p><h1>Product catalog</h1><p>Live inventory and ordering from the Express/PostgreSQL service.</p></div>
      {session.user ? <div className="commerce-user"><span>{session.user.name} · {session.user.role}</span><button className="btn-secondary" onClick={() => { commerceService.clearSession(); setSession({ token: null, user: null }); }}>Sign out</button></div> : null}
    </section>
    {message ? <div className="commerce-message" role="status">{message}</div> : null}
    <div className="commerce-layout">
      <section><div className="commerce-grid">{loading ? <p>Loading catalog…</p> : products.map((product) => <article className="commerce-product" key={product.id}>
        <div className="commerce-product-art">{product.name.slice(0, 1).toUpperCase()}</div><h2>{product.name}</h2><p>{product.description || 'No description provided.'}</p><div className="commerce-product-foot"><strong>{price(product.price_cents, product.currency)}</strong><span>{product.stock_quantity} in stock</span></div><button className="btn-primary" disabled={!product.stock_quantity} onClick={() => addItem(product)}>Add to cart</button>
      </article>)}</div></section>
      <aside className="commerce-aside">
        {!session.user ? <form className="commerce-auth" onSubmit={submitAuth}><h2>{mode === 'login' ? 'Sign in' : 'Create account'}</h2>{mode === 'signup' ? <label>Name<input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label> : null}<label>Email<input required type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label><label>Password<input required type="password" minLength="8" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label><button className="btn-primary btn-block">{mode === 'login' ? 'Sign in' : 'Create account'}</button><button type="button" className="commerce-link" onClick={() => setMode(mode === 'login' ? 'signup' : 'login')}>{mode === 'login' ? 'Need an account?' : 'Already have an account?'}</button></form> : null}
        <section className="commerce-cart"><h2>Cart <span>{cart.length}</span></h2>{cart.length ? <>{cart.map((item) => <div className="commerce-cart-row" key={item.id}><div><strong>{item.name}</strong><small>{price(item.price_cents, item.currency)}</small></div><div className="commerce-quantity"><button onClick={() => changeQuantity(item.id, -1)}>−</button><span>{item.quantity}</span><button disabled={item.quantity >= item.stock_quantity} onClick={() => changeQuantity(item.id, 1)}>+</button></div></div>)}<div className="commerce-total"><span>Total</span><strong>{price(total)}</strong></div><button className="btn-primary btn-block" onClick={checkout}>Place order</button></> : <p>Your cart is empty.</p>}</section>
      </aside>
    </div>
  </div>;
}
