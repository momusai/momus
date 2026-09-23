// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    'intro',
    'quickstart',
    {
      type: 'category',
      label: 'Concepts',
      items: ['detection', 'the-judge'],
    },
    {
      type: 'category',
      label: 'Guides',
      items: [
        'writing-attacks',
        'adapters',
        'output-and-ci',
        'evidence-store',
        'pack-integrity',
      ],
    },
    'cli-reference',
  ],
};

export default sidebars;
