import React, { useRef } from 'react';
import { MonacoQueryFieldLazy } from './MonacoQueryFieldLazy';
import { Props as MonacoProps } from './MonacoQueryFieldProps';

// NOTE: in not-explore modes we want to run the query on onBlur.

// the props are mostly what is the inner monaco widget,
// except the `on*` callbacks
type Props = Omit<MonacoProps, 'onRunQuery' | 'onBlur'> & {
  onChange: (query: string) => void;
  onRunQuery: () => void;
  onBlur?: () => void;
  isExplore: boolean;
};

export const MonacoQueryFieldWrapper = (props: Props) => {
  const lastRunValueRef = useRef<string | null>(null);
  const { isExplore, onBlur, onRunQuery, onChange, ...rest } = props;

  const handleRunQuery = (value: string) => {
    lastRunValueRef.current = value;
    onChange(value);
    onRunQuery();
  };

  const handleBlur = (value: string) => {
    onBlur?.();

    if (!isExplore) {
      // is the current value different from the last-time-executed value?
      if (value !== lastRunValueRef.current) {
        handleRunQuery(value);
      }
    }
  };

  return <MonacoQueryFieldLazy onRunQuery={handleRunQuery} onBlur={handleBlur} {...rest} />;
};
