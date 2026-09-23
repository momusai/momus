// @ts-check
// Docusaurus config for the Momus documentation site.
// See: https://docusaurus.io/docs/api/docusaurus-config

import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Momus',
  tagline: 'The harshest critic your AI will ever face.',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://momus.dev',
  baseUrl: '/',

  organizationName: 'momus-ai',
  projectName: 'momus',

  onBrokenLinks: 'warn',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          routeBasePath: '/', // docs are the site root
          editUrl: 'https://github.com/momus-ai/momus/tree/main/website/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'Momus',
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docs',
            position: 'left',
            label: 'Docs',
          },
          {
            href: 'https://github.com/momus-ai/momus',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {label: 'Introduction', to: '/'},
              {label: 'Quickstart', to: '/quickstart'},
              {label: 'Writing attacks', to: '/writing-attacks'},
            ],
          },
          {
            title: 'Project',
            items: [
              {label: 'GitHub', href: 'https://github.com/momus-ai/momus'},
              {label: 'Roadmap', href: 'https://github.com/momus-ai/momus/blob/main/ROADMAP.md'},
              {label: 'Contributing', href: 'https://github.com/momus-ai/momus/blob/main/CONTRIBUTING.md'},
            ],
          },
        ],
        copyright: `Momus is free and open source, Apache-2.0. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['bash', 'yaml', 'go', 'json'],
      },
    }),
};

export default config;
