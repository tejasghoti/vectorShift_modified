import { createTheme } from '@mui/material/styles';

export const appTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#6A2FE8' },
    secondary: { main: '#9D5CFF' },
    background: {
      default: '#0D0716',
      paper: 'rgba(30,18,50,0.75)'
    },
    text: { primary: '#EFE9F9', secondary: '#BFAEDB' }
  },
  shape: { borderRadius: 12 },
  typography: {
    fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Oxygen, Ubuntu, Cantarell, Open Sans, Helvetica Neue, sans-serif',
    h1: { fontSize: '2rem', fontWeight: 600, background: 'linear-gradient(90deg,#B57CFF,#6A2FE8)', WebkitBackgroundClip: 'text', color: 'transparent' }
  },
  components: {
    MuiPaper: { styleOverrides: { root: { backdropFilter: 'blur(12px)', border: '1px solid rgba(255,255,255,0.08)' } } },
    MuiButton: { styleOverrides: { root: { textTransform: 'none', fontWeight: 500, borderRadius: 10 } } }
  }
});
